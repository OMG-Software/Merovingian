// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/space_hierarchy.hpp"

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/database/persistent_store.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <ranges>
#include <set>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

#include <sodium.h>

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
        if (input.empty() || sodium_init() < 0)
        {
            return {};
        }
        auto const variant = sodium_base64_VARIANT_URLSAFE_NO_PADDING;
        auto output = std::string(sodium_base64_ENCODED_LEN(input.size(), variant), '\0');
        std::ignore = sodium_bin2base64(output.data(), output.size(),
                                        reinterpret_cast<unsigned char const*>(input.data()), input.size(), variant);
        output.resize(std::char_traits<char>::length(output.c_str()));
        return output;
    }

    [[nodiscard]] auto base64url_decode(std::string_view input) -> std::string
    {
        if (input.empty() || sodium_init() < 0)
        {
            return {};
        }
        auto output = std::string((input.size() * 3U) / 4U + 3U, '\0');
        auto decoded_length = std::size_t{0U};
        if (sodium_base642bin(reinterpret_cast<unsigned char*>(output.data()), output.size(), input.data(),
                              input.size(), nullptr, &decoded_length, nullptr,
                              sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0)
        {
            return {};
        }
        output.resize(decoded_length);
        return output;
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
        for (auto const& event : store.events)
        {
            if (event.event_id == event_id)
            {
                return &event;
            }
        }
        return nullptr;
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
        }

        if (world_readable(store, room_id))
        {
            return true;
        }

        return false;
    }

    [[nodiscard]] auto can_view_room_federation(database::PersistentStore const& store, std::string_view room_id)
        -> bool
    {
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
        }
        if (world_readable(store, room_id))
        {
            return true;
        }
        return false;
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

    [[nodiscard]] auto room_summary_object(database::PersistentStore const& store, std::string_view room_id,
                                           bool include_children_state) -> canonicaljson::Object
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

    [[nodiscard]] auto collect_visible_room_ids_client(database::PersistentStore const& store, std::string_view user_id,
                                                       std::string_view root_room_id, std::size_t max_depth,
                                                       bool suggested_only) -> std::vector<std::string>
    {
        auto result = std::vector<std::string>{};
        auto visited = std::unordered_set<std::string>{};
        auto stack = std::vector<std::pair<std::string, std::size_t>>{};
        stack.emplace_back(std::string{root_room_id}, 0U);

        while (!stack.empty())
        {
            auto [room_id, depth] = stack.back();
            stack.pop_back();

            if (!room_exists(store, room_id) || !can_view_room_client(store, user_id, room_id))
            {
                continue;
            }
            if (!visited.insert(room_id).second)
            {
                continue;
            }
            result.push_back(room_id);

            if (depth >= max_depth || !is_space(store, room_id))
            {
                continue;
            }

            auto children = space_children(store, room_id);
            // Push in reverse order so that when popped the original order is preserved
            // (children are emitted in the order they appear in state).
            for (auto it = children.rbegin(); it != children.rend(); ++it)
            {
                if (suggested_only && !it->suggested)
                {
                    continue;
                }
                stack.emplace_back(it->room_id, depth + 1U);
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
    auto constexpr max_limit = std::size_t{1000U};
    auto constexpr default_max_depth = std::size_t{3U};
    auto constexpr hard_max_depth = std::size_t{10U};

    auto limit = request.limit.value_or(default_limit);
    if (limit == 0U)
    {
        return {400U, matrix_error("M_INVALID_PARAM", "limit must be greater than zero")};
    }
    limit = std::min(limit, max_limit);

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

    auto const all_room_ids =
        collect_visible_room_ids_client(store, user_id, request.room_id, max_depth, suggested_only);

    if (offset > all_room_ids.size())
    {
        offset = all_room_ids.size();
    }

    auto rooms = canonicaljson::Array{};
    auto const end = std::min(offset + limit, all_room_ids.size());
    for (auto i = offset; i < end; ++i)
    {
        rooms.push_back(json_obj(room_summary_object(store, all_room_ids[i], true)));
    }

    auto response = canonicaljson::Object{};
    response.push_back(json_member("rooms", json_arr(std::move(rooms))));
    if (end < all_room_ids.size())
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
                                               bool suggested_only) -> std::string
{
    auto const& store = runtime.database.persistent_store;

    if (!room_exists(store, room_id) || !can_view_room_federation(store, room_id))
    {
        return {};
    }

    auto children = canonicaljson::Array{};
    if (is_space(store, room_id))
    {
        for (auto const& child : space_children(store, room_id))
        {
            if (suggested_only && !child.suggested)
            {
                continue;
            }
            if (!room_exists(store, child.room_id) || !can_view_room_federation(store, child.room_id))
            {
                continue;
            }
            children.push_back(json_obj(room_summary_object(store, child.room_id, true)));
        }
    }

    auto response = canonicaljson::Object{};
    response.push_back(json_member("room", json_obj(room_summary_object(store, room_id, true))));
    response.push_back(json_member("children", json_arr(std::move(children))));

    auto const serialized = canonicaljson::serialize_canonical(json_obj(std::move(response)));
    return serialized.error == canonicaljson::CanonicalJsonError::none ? serialized.output : std::string{};
}

} // namespace merovingian::homeserver
