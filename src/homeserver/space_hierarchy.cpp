// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/space_hierarchy.hpp"

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/core/query_params.hpp"
#include "merovingian/core/secret_buffer.hpp"
#include "merovingian/crypto/encoding.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/federation/event_query.hpp"
#include "merovingian/federation/outbound_transaction.hpp"
#include "merovingian/federation/security.hpp"
#include "merovingian/homeserver/client_outbound_proxy.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/request_lock.hpp"
#include "merovingian/homeserver/room_service.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <map>
#include <optional>
#include <ranges>
#include <set>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

namespace merovingian::homeserver
{
namespace
{

    // ---- Small canonical-JSON convenience builders ----------------------------

    [[nodiscard]] auto json_str(std::string_view value) -> canonicaljson::Value
    {
        return canonicaljson::Value{std::string{value}};
    }

    [[nodiscard]] auto json_int(std::int64_t value) -> canonicaljson::Value
    {
        return canonicaljson::Value{value};
    }

    [[nodiscard]] auto json_bool(bool value) -> canonicaljson::Value
    {
        return canonicaljson::Value{value};
    }

    [[nodiscard]] auto json_arr(canonicaljson::Array items) -> canonicaljson::Value
    {
        return canonicaljson::Value{std::move(items)};
    }

    [[nodiscard]] auto json_obj(canonicaljson::Object members) -> canonicaljson::Value
    {
        return canonicaljson::Value{std::move(members)};
    }

    [[nodiscard]] auto json_member(std::string key, canonicaljson::Value value) -> canonicaljson::ObjectMember
    {
        return canonicaljson::make_member(std::move(key), std::move(value));
    }

    // ---- Canonical-JSON object accessors --------------------------------------

    [[nodiscard]] auto object_member(canonicaljson::Object const& object, std::string_view key) noexcept
        -> canonicaljson::Value const*
    {
        for (auto const& member : object)
        {
            if (member.key == key)
            {
                return member.value.get();
            }
        }
        return nullptr;
    }

    [[nodiscard]] auto string_member(canonicaljson::Object const& object, std::string_view key) noexcept
        -> std::string const*
    {
        auto const* value = object_member(object, key);
        return value == nullptr ? nullptr : std::get_if<std::string>(&value->storage());
    }

    [[nodiscard]] auto int_member(canonicaljson::Object const& object, std::string_view key) noexcept
        -> std::int64_t const*
    {
        auto const* value = object_member(object, key);
        return value == nullptr ? nullptr : std::get_if<std::int64_t>(&value->storage());
    }

    [[nodiscard]] auto bool_member(canonicaljson::Object const& object, std::string_view key) noexcept -> bool const*
    {
        auto const* value = object_member(object, key);
        return value == nullptr ? nullptr : std::get_if<bool>(&value->storage());
    }

    [[nodiscard]] auto object_member_as_object(canonicaljson::Object const& object, std::string_view key) noexcept
        -> canonicaljson::Object const*
    {
        auto const* value = object_member(object, key);
        return value == nullptr ? nullptr : std::get_if<canonicaljson::Object>(&value->storage());
    }

    [[nodiscard]] auto object_member_as_array(canonicaljson::Object const& object, std::string_view key) noexcept
        -> canonicaljson::Array const*
    {
        auto const* value = object_member(object, key);
        return value == nullptr ? nullptr : std::get_if<canonicaljson::Array>(&value->storage());
    }

    // ---- Base64url codec for pagination tokens ----------------------------------

    [[nodiscard]] auto base64url_encode(std::string_view input) -> std::string
    {
        auto const encoded = crypto::base64_urlsafe_encode(input);
        return encoded.value_or("");
    }

    [[nodiscard]] auto base64url_decode(std::string_view input) -> std::string
    {
        auto const decoded = crypto::base64_urlsafe_decode(input);
        return decoded.value_or("");
    }

    // ---- Persistent-store state helpers ---------------------------------------

    [[nodiscard]] auto find_state_event(database::PersistentStore const& store, std::string_view room_id,
                                        std::string_view event_type, std::string_view state_key)
        -> database::PersistentStateEvent const*
    {
        for (auto const& state : store.state)
        {
            if (state.room_id == room_id && state.event_type == event_type && state.state_key == state_key)
            {
                return &state;
            }
        }
        return nullptr;
    }

    [[nodiscard]] auto find_event(database::PersistentStore const& store, std::string_view event_id)
        -> database::PersistentEvent const*
    {
        auto const found = store.events.find(event_id);
        return found == store.events.end() ? nullptr : &*found;
    }

    [[nodiscard]] auto state_event_json(database::PersistentStore const& store, std::string_view room_id,
                                        std::string_view event_type, std::string_view state_key = {})
        -> std::optional<std::string>
    {
        auto const* state = find_state_event(store, room_id, event_type, state_key);
        if (state == nullptr)
        {
            return std::nullopt;
        }
        auto const* event = find_event(store, state->event_id);
        if (event == nullptr)
        {
            return std::nullopt;
        }
        return event->json;
    }

    [[nodiscard]] auto state_event_content(database::PersistentStore const& store, std::string_view room_id,
                                           std::string_view event_type, std::string_view state_key = {})
        -> std::optional<canonicaljson::Object>
    {
        auto const json = state_event_json(store, room_id, event_type, state_key);
        if (!json.has_value())
        {
            return std::nullopt;
        }
        auto const parsed = canonicaljson::parse_lossless(*json);
        if (parsed.error != canonicaljson::ParseError::none)
        {
            return std::nullopt;
        }
        auto const* object = std::get_if<canonicaljson::Object>(&parsed.value.storage());
        if (object == nullptr)
        {
            return std::nullopt;
        }
        auto const* content = object_member_as_object(*object, "content");
        if (content == nullptr)
        {
            return std::nullopt;
        }
        return *content;
    }

    [[nodiscard]] auto state_event_origin_server_ts(database::PersistentStore const& store, std::string_view room_id,
                                                    std::string_view event_type, std::string_view state_key = {})
        -> std::int64_t
    {
        auto const json = state_event_json(store, room_id, event_type, state_key);
        if (!json.has_value())
        {
            return 0;
        }
        auto const parsed = canonicaljson::parse_lossless(*json);
        if (parsed.error != canonicaljson::ParseError::none)
        {
            return 0;
        }
        auto const* object = std::get_if<canonicaljson::Object>(&parsed.value.storage());
        if (object == nullptr)
        {
            return 0;
        }
        auto const* ts = int_member(*object, "origin_server_ts");
        return ts == nullptr ? 0 : *ts;
    }

    [[nodiscard]] auto state_event_sender(database::PersistentStore const& store, std::string_view room_id,
                                          std::string_view event_type, std::string_view state_key = {}) -> std::string
    {
        auto const json = state_event_json(store, room_id, event_type, state_key);
        if (!json.has_value())
        {
            return {};
        }
        auto const parsed = canonicaljson::parse_lossless(*json);
        if (parsed.error != canonicaljson::ParseError::none)
        {
            return {};
        }
        auto const* object = std::get_if<canonicaljson::Object>(&parsed.value.storage());
        if (object == nullptr)
        {
            return {};
        }
        auto const* sender = string_member(*object, "sender");
        return sender == nullptr ? std::string{} : *sender;
    }

    // ---- Room metadata --------------------------------------------------------

    [[nodiscard]] auto room_exists(database::PersistentStore const& store, std::string_view room_id) noexcept -> bool
    {
        for (auto const& room : store.rooms)
        {
            if (room.room_id == room_id)
            {
                return true;
            }
        }
        return false;
    }

    [[nodiscard]] auto joined_member_count(database::PersistentStore const& store, std::string_view room_id) noexcept
        -> std::size_t
    {
        return static_cast<std::size_t>(
            std::ranges::count_if(store.memberships, [room_id](database::PersistentMembership const& membership) {
                return membership.room_id == room_id && membership.membership == "join";
            }));
    }

    [[nodiscard]] auto user_membership(database::PersistentStore const& store, std::string_view room_id,
                                       std::string_view user_id) noexcept -> std::optional<std::string>
    {
        auto const* state = find_state_event(store, room_id, "m.room.member", user_id);
        if (state == nullptr)
        {
            return std::nullopt;
        }
        auto const content = state_event_content(store, room_id, "m.room.member", user_id);
        if (!content.has_value())
        {
            return std::nullopt;
        }
        auto const* membership = string_member(*content, "membership");
        if (membership == nullptr)
        {
            return std::nullopt;
        }
        return std::string{*membership};
    }

    [[nodiscard]] auto room_type(database::PersistentStore const& store, std::string_view room_id)
        -> std::optional<std::string>
    {
        auto const content = state_event_content(store, room_id, "m.room.create");
        if (!content.has_value())
        {
            return std::nullopt;
        }
        auto const* type = string_member(*content, "type");
        if (type == nullptr)
        {
            return std::nullopt;
        }
        return std::string{*type};
    }

    [[nodiscard]] auto is_space(database::PersistentStore const& store, std::string_view room_id) -> bool
    {
        auto const type = room_type(store, room_id);
        return type.has_value() && type.value() == "m.space";
    }

    [[nodiscard]] auto room_version(database::PersistentStore const& store, std::string_view room_id)
        -> std::optional<std::string>
    {
        auto const content = state_event_content(store, room_id, "m.room.create");
        if (!content.has_value())
        {
            return std::nullopt;
        }
        auto const* version = string_member(*content, "room_version");
        if (version == nullptr)
        {
            return std::nullopt;
        }
        return std::string{*version};
    }

    [[nodiscard]] auto join_rule(database::PersistentStore const& store, std::string_view room_id)
        -> std::optional<std::string>
    {
        auto const content = state_event_content(store, room_id, "m.room.join_rules");
        if (!content.has_value())
        {
            return std::nullopt;
        }
        auto const* rule = string_member(*content, "join_rule");
        if (rule == nullptr)
        {
            return std::nullopt;
        }
        return std::string{*rule};
    }

    [[nodiscard]] auto history_visibility(database::PersistentStore const& store, std::string_view room_id)
        -> std::optional<std::string>
    {
        auto const content = state_event_content(store, room_id, "m.room.history_visibility");
        if (!content.has_value())
        {
            return std::nullopt;
        }
        auto const* visibility = string_member(*content, "history_visibility");
        if (visibility == nullptr)
        {
            return std::nullopt;
        }
        return std::string{*visibility};
    }

    [[nodiscard]] auto guest_can_join(database::PersistentStore const& store, std::string_view room_id) -> bool
    {
        auto const content = state_event_content(store, room_id, "m.room.guest_access");
        if (!content.has_value())
        {
            return false;
        }
        auto const* guest_access = string_member(*content, "guest_access");
        return guest_access != nullptr && *guest_access == "can_join";
    }

    [[nodiscard]] auto world_readable(database::PersistentStore const& store, std::string_view room_id) -> bool
    {
        auto const visibility = history_visibility(store, room_id);
        return visibility.has_value() && visibility.value() == "world_readable";
    }

    [[nodiscard]] auto allowed_room_ids(database::PersistentStore const& store, std::string_view room_id)
        -> std::vector<std::string>
    {
        auto ids = std::vector<std::string>{};
        auto const content = state_event_content(store, room_id, "m.room.join_rules");
        if (!content.has_value())
        {
            return ids;
        }
        auto const* allow = object_member_as_array(*content, "allow");
        if (allow == nullptr)
        {
            return ids;
        }
        for (auto const& item : *allow)
        {
            auto const* obj = std::get_if<canonicaljson::Object>(&item.storage());
            if (obj == nullptr)
            {
                continue;
            }
            auto const* type = string_member(*obj, "type");
            if (type == nullptr || *type != "m.room_membership")
            {
                continue;
            }
            auto const* id = string_member(*obj, "room_id");
            if (id != nullptr)
            {
                ids.emplace_back(*id);
            }
        }
        return ids;
    }

    // ---- Visibility checks ----------------------------------------------------

    // True when `user_id` is joined to at least one of `room_ids`, as this server's current state of
    // each of them says. A room this server holds no state for counts as not joined: a local user
    // can only be joined to a room the server holds.
    [[nodiscard]] auto user_joined_to_any(database::PersistentStore const& store, std::string_view user_id,
                                          std::vector<std::string> const& room_ids) -> bool
    {
        return std::ranges::any_of(room_ids, [&](std::string const& room_id) {
            auto const membership = user_membership(store, room_id, user_id);
            return membership.has_value() && membership.value() == "join";
        });
    }

    // Spec (CS API, GET /hierarchy, 200 `rooms`): the server returns a room the user is joined to or
    // invited to, or that is `public`, `knock`/`knock_restricted`, or `world_readable`, or that is
    // `restricted` "provided the user meets one of the specified conditions": here, joined to one of
    // the rooms the join rule names.
    [[nodiscard]] auto can_view_room_client(database::PersistentStore const& store, std::string_view user_id,
                                            std::string_view room_id) -> bool
    {
        auto const membership = user_membership(store, room_id, user_id);
        if (membership.has_value())
        {
            auto const m = membership.value();
            if (m == "join" || m == "invite")
            {
                return true;
            }
        }

        auto const rule = join_rule(store, room_id);
        if (rule.has_value())
        {
            if (rule.value() == "public")
            {
                return true;
            }
            if (rule.value() == "knock" || rule.value() == "knock_restricted")
            {
                return true;
            }
            if (rule.value() == "restricted" && user_joined_to_any(store, user_id, allowed_room_ids(store, room_id)))
            {
                return true;
            }
        }

        if (world_readable(store, room_id))
        {
            return true;
        }

        return false;
    }

    // Spec (SS API, GET /hierarchy): "the space-room's children the requesting server could feasibly
    // peek/join". A restricted room is joinable by `origin` while a user of `origin` is joined to a
    // room its join rule names, which is what a resident server checks when it is asked to join one
    // (CS API, Restricted rooms).
    [[nodiscard]] auto can_view_room_federation(database::PersistentStore const& store, std::string_view room_id,
                                                std::string_view origin) -> bool
    {
        // A server with a user already joined to the room is in it, so it can peek it whatever the
        // join rule says; listing such a room as inaccessible would hide it from that server's members.
        if (federation::origin_has_joined_user_in_room(store, room_id, origin))
        {
            return true;
        }
        auto const rule = join_rule(store, room_id);
        if (rule.has_value())
        {
            if (rule.value() == "public")
            {
                return true;
            }
            if (rule.value() == "knock" || rule.value() == "knock_restricted")
            {
                return true;
            }
            if (rule.value() == "restricted")
            {
                auto const allowed = allowed_room_ids(store, room_id);
                if (std::ranges::any_of(allowed, [&](std::string const& allowed_room) {
                        return federation::origin_has_joined_user_in_room(store, allowed_room, origin);
                    }))
                {
                    return true;
                }
            }
        }
        if (world_readable(store, room_id))
        {
            return true;
        }
        return false;
    }

    // The same test for a room this server holds no state for, from the summary another server gave
    // of it: its own `world_readable`, `join_rule` ("When not present, the room is assumed to be
    // `public`") and `allowed_room_ids`. Invites cannot apply: an invite to a local user would have
    // made the room one this server holds.
    [[nodiscard]] auto remote_summary_visible_to(database::PersistentStore const& store, std::string_view user_id,
                                                 canonicaljson::Object const& summary) -> bool
    {
        auto const* readable = bool_member(summary, "world_readable");
        if (readable != nullptr && *readable)
        {
            return true;
        }
        auto const* rule = string_member(summary, "join_rule");
        if (rule == nullptr || *rule == "public" || *rule == "knock" || *rule == "knock_restricted")
        {
            return true;
        }
        if (*rule != "restricted")
        {
            return false;
        }
        auto allowed = std::vector<std::string>{};
        if (auto const* ids = object_member_as_array(summary, "allowed_room_ids"))
        {
            for (auto const& id : *ids)
            {
                if (auto const* text = std::get_if<std::string>(&id.storage()))
                {
                    allowed.push_back(*text);
                }
            }
        }
        return user_joined_to_any(store, user_id, allowed);
    }

    // ---- Space child events ---------------------------------------------------

    struct SpaceChild final
    {
        std::string room_id{};
        std::vector<std::string> via{};
        bool suggested{false};
        std::int64_t origin_server_ts{0};
        std::string sender{};
        canonicaljson::Object content{};
    };

    [[nodiscard]] auto string_array_values(canonicaljson::Array const& array) -> std::vector<std::string>
    {
        auto result = std::vector<std::string>{};
        for (auto const& item : array)
        {
            if (auto const* str = std::get_if<std::string>(&item.storage()))
            {
                result.emplace_back(*str);
            }
        }
        return result;
    }

    [[nodiscard]] auto space_children(database::PersistentStore const& store, std::string_view room_id)
        -> std::vector<SpaceChild>
    {
        auto children = std::vector<SpaceChild>{};
        for (auto const& state : store.state)
        {
            if (state.room_id != room_id || state.event_type != "m.space.child")
            {
                continue;
            }
            auto const content = state_event_content(store, room_id, "m.space.child", state.state_key);
            if (!content.has_value())
            {
                continue;
            }
            auto const* via = object_member_as_array(*content, "via");
            if (via == nullptr || via->empty())
            {
                // A missing or empty via list removes the child from the space.
                continue;
            }
            auto const suggested_ptr = bool_member(*content, "suggested");
            auto const suggested = suggested_ptr != nullptr && *suggested_ptr;

            auto child = SpaceChild{};
            child.room_id = std::string{state.state_key};
            child.via = string_array_values(*via);
            child.suggested = suggested;
            child.origin_server_ts = state_event_origin_server_ts(store, room_id, "m.space.child", state.state_key);
            child.sender = std::string{state_event_sender(store, room_id, "m.space.child", state.state_key)};
            child.content = *content;
            children.push_back(std::move(child));
        }
        return children;
    }

    [[nodiscard]] auto stripped_child_state_event(SpaceChild const& child) -> canonicaljson::Object
    {
        auto stripped = canonicaljson::Object{};
        stripped.push_back(json_member("content", json_obj(child.content)));
        stripped.push_back(json_member("origin_server_ts", json_int(child.origin_server_ts)));
        stripped.push_back(json_member("sender", json_str(child.sender)));
        stripped.push_back(json_member("state_key", json_str(child.room_id)));
        stripped.push_back(json_member("type", json_str("m.space.child")));
        return stripped;
    }

    // ---- Room summary chunk ---------------------------------------------------

    // With `suggested_only`, `children_state` carries the suggested links only: the request asks the
    // server to "only consider suggested rooms", and a link to an unsuggested room is not one.
    [[nodiscard]] auto room_summary_object(database::PersistentStore const& store, std::string_view room_id,
                                           bool include_children_state, bool suggested_only) -> canonicaljson::Object
    {
        auto summary = canonicaljson::Object{};
        summary.push_back(json_member("room_id", json_str(room_id)));

        auto const count = static_cast<std::int64_t>(joined_member_count(store, room_id));
        summary.push_back(json_member("num_joined_members", json_int(count)));

        summary.push_back(json_member("guest_can_join", json_bool(guest_can_join(store, room_id))));
        summary.push_back(json_member("world_readable", json_bool(world_readable(store, room_id))));

        if (auto const name = state_event_content(store, room_id, "m.room.name"))
        {
            if (auto const* value = string_member(*name, "name"))
            {
                summary.push_back(json_member("name", json_str(*value)));
            }
        }
        if (auto const topic = state_event_content(store, room_id, "m.room.topic"))
        {
            if (auto const* value = string_member(*topic, "topic"))
            {
                summary.push_back(json_member("topic", json_str(*value)));
            }
        }
        if (auto const alias = state_event_content(store, room_id, "m.room.canonical_alias"))
        {
            if (auto const* value = string_member(*alias, "alias"))
            {
                summary.push_back(json_member("canonical_alias", json_str(*value)));
            }
        }
        if (auto const avatar = state_event_content(store, room_id, "m.room.avatar"))
        {
            if (auto const* value = string_member(*avatar, "url"))
            {
                summary.push_back(json_member("avatar_url", json_str(*value)));
            }
        }
        if (auto const rule = join_rule(store, room_id))
        {
            summary.push_back(json_member("join_rule", json_str(rule.value())));
        }
        if (auto const type = room_type(store, room_id))
        {
            summary.push_back(json_member("room_type", json_str(type.value())));
        }
        if (auto const version = room_version(store, room_id))
        {
            summary.push_back(json_member("room_version", json_str(version.value())));
        }
        if (auto const encryption = state_event_content(store, room_id, "m.room.encryption"))
        {
            if (auto const* algorithm = string_member(*encryption, "algorithm"))
            {
                summary.push_back(json_member("encryption", json_str(*algorithm)));
            }
        }

        auto const allowed_ids = allowed_room_ids(store, room_id);
        if (!allowed_ids.empty())
        {
            auto allowed_array = canonicaljson::Array{};
            for (auto const& id : allowed_ids)
            {
                allowed_array.push_back(json_str(id));
            }
            summary.push_back(json_member("allowed_room_ids", json_arr(std::move(allowed_array))));
        }

        if (include_children_state && is_space(store, room_id))
        {
            auto children_state = canonicaljson::Array{};
            for (auto const& child : space_children(store, room_id))
            {
                if (suggested_only && !child.suggested)
                {
                    continue;
                }
                children_state.push_back(json_obj(stripped_child_state_event(child)));
            }
            summary.push_back(json_member("children_state", json_arr(std::move(children_state))));
        }
        else
        {
            summary.push_back(json_member("children_state", json_arr(canonicaljson::Array{})));
        }

        return summary;
    }

    // ---- Depth-first traversal ------------------------------------------------

    // ---- Child rooms this server holds no state for ------------------------------
    //
    // Spec (CS API, Server behaviour): "In the case where the server does not have access to the
    // state of a child room, it can request the information over federation with the
    // GET /hierarchy API ... the local data should be used instead of the remote server's data."
    // Everything a remote server says is untrusted: only spec fields are copied, each with its
    // type checked, and the user is shown a room only if the summary itself says they may see it.

    // Bounds on one walk, so a space whose links name many unknown rooms, or a server that answers
    // with a very large body, cannot make one request do unbounded work.
    constexpr auto max_remote_requests_per_walk = std::size_t{16U};
    constexpr auto max_remote_servers_per_room = std::size_t{3U};
    constexpr auto max_remote_links_per_room = std::size_t{1024U};
    constexpr auto max_remote_allowed_rooms = std::size_t{32U};

    // A room as another server described it: the summary to show, and the links to follow.
    struct RemoteRoom final
    {
        canonicaljson::Object summary{};
        std::vector<SpaceChild> links{};
        bool is_space{false};
        // True when the answer carried the room's `children_state`, so the links are complete. A
        // federation `children` chunk need not carry it (the spec's chunk has none).
        bool has_links{false};
    };

    struct RemoteAnswer final
    {
        RemoteRoom room{};
        std::vector<RemoteRoom> children{};
        std::vector<std::string> inaccessible{};
    };

    // Copies `key` from `in` to `out` when it is a string. False when it is present with another type.
    [[nodiscard]] auto copy_optional_string(canonicaljson::Object const& in, std::string_view key,
                                            canonicaljson::Object& out) -> bool
    {
        auto const* value = object_member(in, key);
        if (value == nullptr)
        {
            return true;
        }
        auto const* text = std::get_if<std::string>(&value->storage());
        if (text == nullptr)
        {
            return false;
        }
        out.push_back(json_member(std::string{key}, json_str(*text)));
        return true;
    }

    // One `m.space.child` entry of a remote `children_state`, rebuilt from its spec fields only.
    [[nodiscard]] auto sanitise_remote_link(canonicaljson::Value const& item) -> std::optional<SpaceChild>
    {
        auto const* event = std::get_if<canonicaljson::Object>(&item.storage());
        if (event == nullptr)
        {
            return std::nullopt;
        }
        auto const* type = string_member(*event, "type");
        auto const* state_key = string_member(*event, "state_key");
        auto const* sender = string_member(*event, "sender");
        auto const* timestamp = int_member(*event, "origin_server_ts");
        auto const* content = object_member_as_object(*event, "content");
        if (type == nullptr || *type != "m.space.child" || state_key == nullptr || state_key->empty() ||
            sender == nullptr || timestamp == nullptr || content == nullptr)
        {
            return std::nullopt;
        }
        auto const* via = object_member_as_array(*content, "via");
        if (via == nullptr)
        {
            return std::nullopt;
        }
        auto servers = string_array_values(*via);
        if (servers.empty())
        {
            // An empty `via` removes the child from the space.
            return std::nullopt;
        }
        auto link = SpaceChild{};
        link.room_id = *state_key;
        link.via = std::move(servers);
        auto const* suggested = bool_member(*content, "suggested");
        link.suggested = suggested != nullptr && *suggested;
        link.origin_server_ts = *timestamp;
        link.sender = *sender;
        auto kept = canonicaljson::Object{};
        auto via_values = canonicaljson::Array{};
        for (auto const& server : link.via)
        {
            via_values.push_back(json_str(server));
        }
        kept.push_back(json_member("via", json_arr(std::move(via_values))));
        if (suggested != nullptr)
        {
            kept.push_back(json_member("suggested", json_bool(*suggested)));
        }
        if (auto const* order = string_member(*content, "order"))
        {
            kept.push_back(json_member("order", json_str(*order)));
        }
        link.content = std::move(kept);
        return link;
    }

    // A remote room chunk (the `room` or one entry of `children`), or nullopt when it is not one.
    [[nodiscard]] auto sanitise_remote_room(canonicaljson::Value const& value, bool suggested_only)
        -> std::optional<RemoteRoom>
    {
        auto const* in = std::get_if<canonicaljson::Object>(&value.storage());
        if (in == nullptr)
        {
            return std::nullopt;
        }
        auto const* room_id = string_member(*in, "room_id");
        if (room_id == nullptr || room_id->empty())
        {
            return std::nullopt;
        }

        auto summary = canonicaljson::Object{};
        summary.push_back(json_member("room_id", json_str(*room_id)));

        auto const* joined = int_member(*in, "num_joined_members");
        summary.push_back(json_member("num_joined_members", json_int(joined == nullptr || *joined < 0 ? 0 : *joined)));
        for (auto const* flag : {"guest_can_join", "world_readable"})
        {
            auto const* member = object_member(*in, flag);
            if (member != nullptr && std::get_if<bool>(&member->storage()) == nullptr)
            {
                return std::nullopt;
            }
            auto const* value_bool = bool_member(*in, flag);
            summary.push_back(json_member(flag, json_bool(value_bool != nullptr && *value_bool)));
        }
        for (auto const* key :
             {"name", "topic", "canonical_alias", "avatar_url", "join_rule", "room_type", "room_version", "encryption"})
        {
            if (!copy_optional_string(*in, key, summary))
            {
                return std::nullopt;
            }
        }
        if (auto const* allowed = object_member_as_array(*in, "allowed_room_ids"))
        {
            auto ids = canonicaljson::Array{};
            for (auto const& id : *allowed)
            {
                if (auto const* text = std::get_if<std::string>(&id.storage());
                    text != nullptr && ids.size() < max_remote_allowed_rooms)
                {
                    ids.push_back(json_str(*text));
                }
            }
            if (!ids.empty())
            {
                summary.push_back(json_member("allowed_room_ids", json_arr(std::move(ids))));
            }
        }

        auto room = RemoteRoom{};
        auto const* type = string_member(*in, "room_type");
        room.is_space = type != nullptr && *type == "m.space";

        auto children_state = canonicaljson::Array{};
        if (room.is_space)
        {
            if (auto const* links = object_member_as_array(*in, "children_state"))
            {
                room.has_links = true;
                for (auto const& item : *links)
                {
                    if (room.links.size() >= max_remote_links_per_room)
                    {
                        break;
                    }
                    auto link = sanitise_remote_link(item);
                    if (!link.has_value() || (suggested_only && !link->suggested))
                    {
                        continue;
                    }
                    children_state.push_back(json_obj(stripped_child_state_event(*link)));
                    room.links.push_back(std::move(*link));
                }
            }
        }
        summary.push_back(json_member("children_state", json_arr(std::move(children_state))));
        room.summary = std::move(summary);
        return room;
    }

    // Spec (SS API, GET /hierarchy, 200): `room`, `children` and `inaccessible_children`. The answer
    // is accepted only for the room that was asked about.
    [[nodiscard]] auto parse_remote_answer(std::string_view body, std::string_view requested_room_id,
                                           bool suggested_only) -> std::optional<RemoteAnswer>
    {
        auto const parsed = canonicaljson::parse_lossless(body);
        if (parsed.error != canonicaljson::ParseError::none)
        {
            return std::nullopt;
        }
        auto const* object = std::get_if<canonicaljson::Object>(&parsed.value.storage());
        if (object == nullptr)
        {
            return std::nullopt;
        }
        auto const* room_value = object_member(*object, "room");
        if (room_value == nullptr)
        {
            return std::nullopt;
        }
        auto room = sanitise_remote_room(*room_value, suggested_only);
        if (!room.has_value())
        {
            return std::nullopt;
        }
        auto const* answered_id = string_member(*std::get_if<canonicaljson::Object>(&room_value->storage()), "room_id");
        if (answered_id == nullptr || *answered_id != requested_room_id)
        {
            return std::nullopt;
        }

        auto answer = RemoteAnswer{};
        answer.room = std::move(*room);

        // Only a room the answered space itself links to is taken from `children`: another server
        // does not get to describe rooms nothing in the walk refers to.
        auto declared = std::unordered_set<std::string>{};
        for (auto const& link : answer.room.links)
        {
            declared.insert(link.room_id);
        }
        if (auto const* children = object_member_as_array(*object, "children"))
        {
            for (auto const& item : *children)
            {
                if (answer.children.size() >= max_remote_links_per_room)
                {
                    break;
                }
                auto child = sanitise_remote_room(item, suggested_only);
                if (!child.has_value())
                {
                    continue;
                }
                auto const* child_id = string_member(child->summary, "room_id");
                if (child_id != nullptr && declared.contains(*child_id))
                {
                    answer.children.push_back(std::move(*child));
                }
            }
        }
        if (auto const* inaccessible = object_member_as_array(*object, "inaccessible_children"))
        {
            for (auto const& item : *inaccessible)
            {
                if (auto const* text = std::get_if<std::string>(&item.storage());
                    text != nullptr && declared.contains(*text) &&
                    answer.inaccessible.size() < max_remote_links_per_room)
                {
                    answer.inaccessible.push_back(*text);
                }
            }
        }
        return answer;
    }

    enum class RemoteStatus : std::uint8_t
    {
        found,
        absent,
        refused,
    };

    struct RemoteLookup final
    {
        RemoteStatus status{RemoteStatus::absent};
        RemoteRoom room{};
    };

    // Asks other servers for the rooms of one hierarchy walk. The first request takes a slot in the
    // client-outbound budget, held until the walk ends, and starts the one deadline every request
    // draws from (ADR-0079); a refused slot refuses the walk. The runtime lock is released only
    // around the network call, so every read of runtime state happens outside it.
    class RemoteHierarchy final
    {
    public:
        RemoteHierarchy(HomeserverRuntime& runtime, std::string client_key, bool suggested_only)
            : m_runtime{runtime}
            , m_client_key{std::move(client_key)}
            , m_suggested_only{suggested_only}
        {
        }

        [[nodiscard]] auto lookup(std::string const& room_id, std::vector<std::string> const& via) -> RemoteLookup
        {
            if (m_inaccessible.contains(room_id))
            {
                return {};
            }
            if (auto const known = m_known.find(room_id); known != m_known.end())
            {
                return {RemoteStatus::found, known->second};
            }
            for (auto const& server : candidate_servers(via))
            {
                if (m_requests >= max_remote_requests_per_walk)
                {
                    break;
                }
                if (!m_slot.has_value())
                {
                    auto taken = admit_client_outbound_proxy(m_runtime, m_client_key);
                    if (!taken.has_value())
                    {
                        return {RemoteStatus::refused, {}};
                    }
                    m_slot.emplace(std::move(*taken));
                    m_deadline.emplace(effective_client_outbound_deadline(
                        m_runtime, m_runtime.client_outbound_proxy_policy.directory_deadline_seconds));
                }
                if (m_deadline->expired())
                {
                    break;
                }
                ++m_requests;
                auto answer = ask(server, room_id);
                if (!answer.has_value())
                {
                    continue;
                }
                remember(room_id, std::move(*answer));
                if (auto const known = m_known.find(room_id); known != m_known.end())
                {
                    return {RemoteStatus::found, known->second};
                }
            }
            return {};
        }

    private:
        // The servers named by a link's `via`, other than this one, in order, without repeats.
        [[nodiscard]] auto candidate_servers(std::vector<std::string> const& via) const -> std::vector<std::string>
        {
            auto const our_server = std::string{m_runtime.config.server().server_name};
            auto servers = std::vector<std::string>{};
            for (auto const& server : via)
            {
                if (servers.size() >= max_remote_servers_per_room)
                {
                    break;
                }
                if (server == our_server || !federation::server_name_is_valid(server) ||
                    std::ranges::find(servers, server) != servers.end())
                {
                    continue;
                }
                servers.push_back(server);
            }
            return servers;
        }

        [[nodiscard]] auto ask(std::string const& server, std::string const& room_id) -> std::optional<RemoteAnswer>
        {
            wire_federation_callbacks(m_runtime);
            auto const our_server = std::string{m_runtime.config.server().server_name};
            auto const signing_key = ensure_runtime_server_signing_key(m_runtime);
            auto const key_id = signing_key.has_value() ? signing_key->key_id : std::string{};
            // Copied while the runtime lock is held, moved into the call: it signs after the lock is released.
            auto secret = core::SecretBuffer{m_runtime.database.signing_secret_key.bytes()};
            auto target =
                std::string{"/_matrix/federation/v1/hierarchy/"} + core::percent_encode_path_component(room_id);
            if (m_suggested_only)
            {
                target += "?suggested_only=true";
            }
            auto const transaction = federation::make_outbound_transaction(server, "GET", target, our_server, {});
            auto const [ok, body] = [&] {
                auto const released = RuntimeLockRelease{};
                return perform_bounded_outbound_call(m_runtime, room_id, transaction, key_id, std::move(secret),
                                                     "space_hierarchy.fetch", m_deadline->remaining_seconds());
            }();
            if (!ok)
            {
                return std::nullopt;
            }
            return parse_remote_answer(body, room_id, m_suggested_only);
        }

        auto remember(std::string const& room_id, RemoteAnswer answer) -> void
        {
            for (auto& child : answer.children)
            {
                auto const* child_id = string_member(child.summary, "room_id");
                // A child space whose answer carried no `children_state` is asked for itself when the
                // walk reaches it; a room already known is not replaced.
                if (child_id == nullptr || *child_id == room_id || (child.is_space && !child.has_links))
                {
                    continue;
                }
                m_known.emplace(*child_id, std::move(child));
            }
            for (auto& id : answer.inaccessible)
            {
                m_inaccessible.insert(std::move(id));
            }
            m_known.insert_or_assign(room_id, std::move(answer.room));
        }

        HomeserverRuntime& m_runtime;
        std::string m_client_key;
        bool m_suggested_only;
        std::optional<http::InFlightBudget::Slot> m_slot{};
        std::optional<OutboundDeadline> m_deadline{};
        std::size_t m_requests{0U};
        std::map<std::string, RemoteRoom, std::less<>> m_known{};
        std::unordered_set<std::string> m_inaccessible{};
    };

    // ---- Depth-first walk for a local user --------------------------------------

    // One room of the walk: a room this server holds is described from its state when the page is
    // built; a remote one carries the summary its server gave.
    struct WalkEntry final
    {
        std::string room_id{};
        std::optional<canonicaljson::Object> remote_summary{};
    };

    struct WalkResult final
    {
        std::vector<WalkEntry> entries{};
        // The client-outbound budget refused a request the walk needed (ADR-0079).
        bool refused{false};
    };

    struct WalkFrame final
    {
        std::string room_id{};
        std::vector<std::string> via{};
        std::size_t depth{0U};
    };

    [[nodiscard]] auto walk_hierarchy_client(HomeserverRuntime& runtime, std::string_view user_id,
                                             std::string_view root_room_id, std::size_t max_depth, bool suggested_only,
                                             std::string const& client_key) -> WalkResult
    {
        auto const& store = runtime.database.persistent_store;
        auto remote = RemoteHierarchy{runtime, client_key, suggested_only};
        auto result = WalkResult{};
        auto visited = std::unordered_set<std::string>{};
        auto stack = std::vector<WalkFrame>{};
        stack.push_back({std::string{root_room_id}, {}, 0U});

        while (!stack.empty())
        {
            auto frame = std::move(stack.back());
            stack.pop_back();
            if (!visited.insert(frame.room_id).second)
            {
                continue;
            }

            auto entry = WalkEntry{frame.room_id, std::nullopt};
            auto links = std::vector<SpaceChild>{};
            if (room_exists(store, frame.room_id))
            {
                // Local state decides, never a remote answer about the same room.
                if (!can_view_room_client(store, user_id, frame.room_id))
                {
                    continue;
                }
                if (is_space(store, frame.room_id))
                {
                    links = space_children(store, frame.room_id);
                }
            }
            else
            {
                auto found = remote.lookup(frame.room_id, frame.via);
                if (found.status == RemoteStatus::refused)
                {
                    result.refused = true;
                    return result;
                }
                if (found.status != RemoteStatus::found ||
                    !remote_summary_visible_to(store, user_id, found.room.summary))
                {
                    continue;
                }
                entry.remote_summary = std::move(found.room.summary);
                links = std::move(found.room.links);
            }
            result.entries.push_back(std::move(entry));

            if (frame.depth >= max_depth)
            {
                continue;
            }
            // Push in reverse order so that when popped the original order is preserved
            // (children are emitted in the order they appear in state).
            for (auto it = links.rbegin(); it != links.rend(); ++it)
            {
                if (suggested_only && !it->suggested)
                {
                    continue;
                }
                stack.push_back({it->room_id, std::move(it->via), frame.depth + 1U});
            }
        }
        return result;
    }

    // ---- Pagination token -----------------------------------------------------

    struct PaginationToken final
    {
        std::string room_id{};
        std::size_t max_depth{0U};
        bool suggested_only{false};
        std::size_t offset{0U};
    };

    [[nodiscard]] auto encode_pagination_token(PaginationToken const& token) -> std::string
    {
        auto object = canonicaljson::Object{};
        object.push_back(json_member("room_id", json_str(token.room_id)));
        object.push_back(json_member("max_depth", json_int(static_cast<std::int64_t>(token.max_depth))));
        object.push_back(json_member("suggested_only", json_bool(token.suggested_only)));
        object.push_back(json_member("offset", json_int(static_cast<std::int64_t>(token.offset))));
        auto const serialized = canonicaljson::serialize_canonical(json_obj(std::move(object)));
        if (serialized.error != canonicaljson::CanonicalJsonError::none)
        {
            return {};
        }
        return base64url_encode(serialized.output);
    }

    [[nodiscard]] auto decode_pagination_token(std::string_view encoded) -> std::optional<PaginationToken>
    {
        auto const decoded = base64url_decode(encoded);
        if (decoded.empty())
        {
            return std::nullopt;
        }
        auto const parsed = canonicaljson::parse_lossless(decoded);
        if (parsed.error != canonicaljson::ParseError::none)
        {
            return std::nullopt;
        }
        auto const* object = std::get_if<canonicaljson::Object>(&parsed.value.storage());
        if (object == nullptr)
        {
            return std::nullopt;
        }
        auto const* room_id = string_member(*object, "room_id");
        auto const* max_depth = int_member(*object, "max_depth");
        auto const* suggested_only = bool_member(*object, "suggested_only");
        auto const* offset = int_member(*object, "offset");
        if (room_id == nullptr || max_depth == nullptr || suggested_only == nullptr || offset == nullptr ||
            *max_depth < 0 || *offset < 0)
        {
            return std::nullopt;
        }
        return PaginationToken{std::string{*room_id}, static_cast<std::size_t>(*max_depth), *suggested_only,
                               static_cast<std::size_t>(*offset)};
    }

    [[nodiscard]] auto matrix_error(std::string_view errcode, std::string_view message) -> std::string
    {
        auto object = canonicaljson::Object{};
        object.push_back(json_member("errcode", json_str(errcode)));
        object.push_back(json_member("error", json_str(message)));
        auto const serialized = canonicaljson::serialize_canonical(json_obj(std::move(object)));
        return serialized.error == canonicaljson::CanonicalJsonError::none ? serialized.output : std::string{};
    }

} // namespace

auto handle_client_space_hierarchy(HomeserverRuntime& runtime, std::string_view user_id,
                                   SpaceHierarchyRequest const& request) -> SpaceHierarchyResult
{
    auto const& store = runtime.database.persistent_store;

    if (!room_exists(store, request.room_id))
    {
        return {404U, matrix_error("M_NOT_FOUND", "room not found")};
    }
    if (!can_view_room_client(store, user_id, request.room_id))
    {
        return {403U, matrix_error("M_FORBIDDEN", "You are not allowed to view this room.")};
    }

    auto constexpr default_limit = std::size_t{100U};
    auto constexpr default_max_depth = std::size_t{3U};
    auto constexpr hard_max_depth = std::size_t{10U};

    auto limit = request.limit.value_or(default_limit);
    if (limit == 0U)
    {
        return {400U, matrix_error("M_INVALID_PARAM", "limit must be greater than zero")};
    }
    limit = std::min(limit, request.max_rooms);

    auto max_depth = request.max_depth.value_or(default_max_depth);
    max_depth = std::min(max_depth, hard_max_depth);

    auto suggested_only = request.suggested_only;
    auto offset = std::size_t{0U};

    if (request.from.has_value() && !request.from->empty())
    {
        auto const token = decode_pagination_token(*request.from);
        if (!token.has_value())
        {
            return {400U, matrix_error("M_INVALID_PARAM", "Unknown pagination token")};
        }
        if (token->room_id != request.room_id || token->max_depth != max_depth ||
            token->suggested_only != suggested_only)
        {
            return {400U, matrix_error("M_INVALID_PARAM",
                                       "max_depth and suggested_only cannot change on paginated requests")};
        }
        offset = token->offset;
    }

    auto const walk =
        walk_hierarchy_client(runtime, user_id, request.room_id, max_depth, suggested_only, request.client_key);
    if (walk.refused)
    {
        auto refusal = SpaceHierarchyResult{
            429U, matrix_error("M_LIMIT_EXCEEDED", "too many concurrent remote lookups, retry shortly")};
        refusal.retry_after_ms = runtime.client_outbound_proxy_policy.retry_after_ms;
        return refusal;
    }
    auto const& all_rooms = walk.entries;

    if (offset > all_rooms.size())
    {
        offset = all_rooms.size();
    }

    auto rooms = canonicaljson::Array{};
    auto const end = std::min(offset + limit, all_rooms.size());
    for (auto i = offset; i < end; ++i)
    {
        rooms.push_back(json_obj(all_rooms[i].remote_summary.has_value()
                                     ? *all_rooms[i].remote_summary
                                     : room_summary_object(store, all_rooms[i].room_id, true, suggested_only)));
    }

    auto response = canonicaljson::Object{};
    response.push_back(json_member("rooms", json_arr(std::move(rooms))));
    if (end < all_rooms.size())
    {
        auto const next_token =
            encode_pagination_token(PaginationToken{std::string{request.room_id}, max_depth, suggested_only, end});
        if (!next_token.empty())
        {
            response.push_back(json_member("next_batch", json_str(next_token)));
        }
    }

    auto const serialized = canonicaljson::serialize_canonical(json_obj(std::move(response)));
    if (serialized.error != canonicaljson::CanonicalJsonError::none)
    {
        return {500U, matrix_error("M_UNKNOWN", "failed to serialize hierarchy response")};
    }
    return {200U, serialized.output};
}

auto build_federation_space_hierarchy_response(HomeserverRuntime const& runtime, std::string_view room_id,
                                               bool suggested_only, std::string_view origin) -> std::string
{
    auto const& store = runtime.database.persistent_store;

    if (!room_exists(store, room_id) || !can_view_room_federation(store, room_id, origin))
    {
        return {};
    }

    auto children = canonicaljson::Array{};
    auto inaccessible = canonicaljson::Array{};
    if (is_space(store, room_id))
    {
        for (auto const& child : space_children(store, room_id))
        {
            if (suggested_only && !child.suggested)
            {
                continue;
            }
            if (!room_exists(store, child.room_id))
            {
                // Spec: "Rooms which the responding server cannot provide details on will be
                // outright excluded from the response instead."
                continue;
            }
            if (!can_view_room_federation(store, child.room_id, origin))
            {
                inaccessible.push_back(json_str(child.room_id));
                continue;
            }
            children.push_back(json_obj(room_summary_object(store, child.room_id, true, suggested_only)));
        }
    }

    auto response = canonicaljson::Object{};
    response.push_back(json_member("room", json_obj(room_summary_object(store, room_id, true, suggested_only))));
    response.push_back(json_member("children", json_arr(std::move(children))));
    response.push_back(json_member("inaccessible_children", json_arr(std::move(inaccessible))));

    auto const serialized = canonicaljson::serialize_canonical(json_obj(std::move(response)));
    return serialized.error == canonicaljson::CanonicalJsonError::none ? serialized.output : std::string{};
}

} // namespace merovingian::homeserver
