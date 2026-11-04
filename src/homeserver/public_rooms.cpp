// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/public_rooms.hpp"

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/core/folded_substring.hpp"
#include "merovingian/core/query_params.hpp"
#include "merovingian/database/persistent_store.hpp"

#include <algorithm>
#include <cstdint>
#include <mutex>
#include <ranges>
#include <string>
#include <unordered_set>
#include <utility>
#include <variant>

namespace merovingian::homeserver
{

namespace
{

    // A string from the content of the room's current state event of this type. An index lookup, never a
    // scan of the store's state (ADR-0344): this runs once per published room under runtime.mutex on a path
    // any federating server can reach.
    [[nodiscard]] auto state_content_string(database::PersistentStore const& store, std::string_view room_id,
                                            std::string_view event_type, std::string_view key)
        -> std::optional<std::string>
    {
        auto const event_id = database::find_current_state_event_id(store, room_id, event_type, {});
        if (!event_id.has_value())
        {
            return std::nullopt;
        }
        auto const event = store.events.find(*event_id);
        if (event == store.events.end())
        {
            return std::nullopt;
        }
        auto const parsed = canonicaljson::parse_lossless(event->json);
        auto const* object = parsed.error == canonicaljson::ParseError::none
                                 ? std::get_if<canonicaljson::Object>(&parsed.value.storage())
                                 : nullptr;
        if (object == nullptr)
        {
            return std::nullopt;
        }
        auto const member_named = [](canonicaljson::Object const& members,
                                     std::string_view name) -> canonicaljson::Value const* {
            auto const found = std::ranges::find_if(members, [name](canonicaljson::ObjectMember const& member) {
                return member.key == name && member.value;
            });
            return found == members.end() ? nullptr : found->value.get();
        };
        auto const* content_value = member_named(*object, "content");
        auto const* content =
            content_value == nullptr ? nullptr : std::get_if<canonicaljson::Object>(&content_value->storage());
        auto const* value_member = content == nullptr ? nullptr : member_named(*content, key);
        auto const* value = value_member == nullptr ? nullptr : std::get_if<std::string>(&value_member->storage());
        return value == nullptr ? std::nullopt : std::optional<std::string>{*value};
    }

    // An empty name, alias or avatar URL is a room without one: the response omits a field the room does not
    // have, and its types do not allow an empty alias or URI.
    [[nodiscard]] auto state_content_text(database::PersistentStore const& store, std::string_view room_id,
                                          std::string_view event_type, std::string_view key)
        -> std::optional<std::string>
    {
        auto value = state_content_string(store, room_id, event_type, key);
        if (value.has_value() && value->empty())
        {
            return std::nullopt;
        }
        return value;
    }

    struct RoomText final
    {
        std::optional<std::string> name{};
        std::optional<std::string> topic{};
        std::optional<std::string> alias{};
    };

    [[nodiscard]] auto read_room_text(database::PersistentStore const& store, std::string_view room_id) -> RoomText
    {
        return {
            state_content_text(store, room_id, "m.room.name", "name"),
            state_content_string(store, room_id, "m.room.topic", "topic"),
            state_content_text(store, room_id, "m.room.canonical_alias", "alias"),
        };
    }

    // Spec, PublishedRoomsChunk: `guest_can_join`, `num_joined_members`, `room_id` and `world_readable` are
    // required; the others are present when the room has them.
    [[nodiscard]] auto room_entry_json(database::PersistentStore const& store, LocalRoom const& room,
                                       RoomText const& text, std::optional<std::string> const& room_type)
        -> std::optional<std::string>
    {
        auto entry = canonicaljson::Object{};
        auto const add_text = [&entry](std::string_view name, std::optional<std::string> const& value) {
            if (value.has_value())
            {
                entry.push_back(canonicaljson::make_member(std::string{name}, canonicaljson::Value{*value}));
            }
        };
        entry.push_back(canonicaljson::make_member("room_id", canonicaljson::Value{room.room_id}));
        entry.push_back(canonicaljson::make_member(
            "num_joined_members", canonicaljson::Value{static_cast<std::int64_t>(room.members.size())}));
        add_text("join_rule", state_content_string(store, room.room_id, "m.room.join_rules", "join_rule"));
        entry.push_back(canonicaljson::make_member(
            "world_readable",
            canonicaljson::Value{state_content_string(store, room.room_id, "m.room.history_visibility",
                                                      "history_visibility") == "world_readable"}));
        entry.push_back(canonicaljson::make_member(
            "guest_can_join", canonicaljson::Value{state_content_string(store, room.room_id, "m.room.guest_access",
                                                                        "guest_access") == "can_join"}));
        add_text("name", text.name);
        add_text("topic", text.topic);
        add_text("canonical_alias", text.alias);
        add_text("avatar_url", state_content_text(store, room.room_id, "m.room.avatar", "url"));
        add_text("room_type", room_type);

        auto serialized = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(entry)});
        if (serialized.error != canonicaljson::CanonicalJsonError::none)
        {
            return std::nullopt;
        }
        return std::move(serialized.output);
    }

} // namespace

auto thirdparty_instance_id_prefix(std::string_view registration_id, std::string_view protocol) -> std::string
{
    return core::percent_encode_path_component(registration_id) + ":" + core::percent_encode_path_component(protocol) +
           ":";
}

auto public_rooms_scope(appservice::AppserviceRegistry const& registry, bool include_all_networks,
                        std::string_view third_party_instance_id) -> PublicRoomsScope
{
    auto scope = PublicRoomsScope{};
    scope.include_all_networks = include_all_networks;
    if (third_party_instance_id.empty())
    {
        return scope;
    }
    scope.network = std::pair<std::string, std::string>{};
    for (auto const& registration : registry.all())
    {
        for (auto const& protocol : registration.protocols)
        {
            auto const prefix = thirdparty_instance_id_prefix(registration.id, protocol);
            if (!third_party_instance_id.starts_with(prefix))
            {
                continue;
            }
            auto const index = third_party_instance_id.substr(prefix.size());
            if (!index.empty() && std::ranges::all_of(index, [](char const digit) {
                    return digit >= '0' && digit <= '9';
                }))
            {
                scope.network = std::pair{registration.id, protocol};
                return scope;
            }
        }
    }
    return scope;
}

auto public_rooms_response_json(LocalDatabase const& database, federation::PublicRoomsFilter const& filter,
                                std::size_t limit, std::size_t since_offset, PublicRoomsScope const& scope,
                                std::size_t max_page_bytes) -> std::string
{
    auto const& store = database.persistent_store;
    auto const page_size = std::max(limit, std::size_t{1U});

    // One linear-time matcher for the request (ADR-0330): a room name or topic can be 64 KiB.
    auto matcher = core::FoldedSubstringMatcher{filter.generic_search_term};
    auto const searching = !filter.generic_search_term.empty();

    // The wanted types as a set: a list of any length costs one lookup per room.
    auto const filtering_types = filter.room_types.has_value();
    auto wanted_types = std::unordered_set<std::string_view>{};
    auto wants_untyped = false;
    if (filtering_types)
    {
        for (auto const& type : *filter.room_types)
        {
            if (type.has_value())
            {
                wanted_types.insert(*type);
            }
            else
            {
                wants_untyped = true;
            }
        }
    }

    // Rooms an appservice published to the networks in scope, found once rather than per room.
    auto network_rooms = std::unordered_set<std::string_view>{};
    for (auto const& entry : store.appservice_directory)
    {
        if (scope.include_all_networks || (scope.network.has_value() && entry.appservice_id == scope.network->first &&
                                           entry.network_id == scope.network->second))
        {
            network_rooms.insert(entry.room_id);
        }
    }

    auto chunk = std::string{};
    auto taken = std::size_t{0U};
    auto page_closed = false;
    // How far the page reached: where the next one starts.
    auto next_offset = since_offset;
    // Every room the scope and filter select, in or out of this page.
    auto selected = std::size_t{0U};
    for (auto const& room : database.rooms)
    {
        // A request naming one network lists only that network's rooms ("Can only be used if
        // include_all_networks is false"); otherwise the homeserver's own directory is listed, with every
        // network's rooms added for include_all_networks. Nothing else is ever listed.
        auto const listed =
            (!scope.network.has_value() && room.directory_public) || network_rooms.contains(room.room_id);
        if (!listed)
        {
            continue;
        }

        // Only what the filter or this page needs is read: past the page, an unfiltered room costs a count.
        auto const may_be_in_page = !page_closed && selected >= since_offset;

        auto room_type = std::optional<std::string>{};
        if (filtering_types || may_be_in_page)
        {
            room_type = state_content_text(store, room.room_id, "m.room.create", "type");
        }
        if (filtering_types && !(room_type.has_value() ? wanted_types.contains(*room_type) : wants_untyped))
        {
            continue;
        }

        auto text = RoomText{};
        if (searching || may_be_in_page)
        {
            text = read_room_text(store, room.room_id);
        }
        if (searching)
        {
            auto const matches = matcher.contains(room.room_id) ||
                                 (text.name.has_value() && matcher.contains(*text.name)) ||
                                 (text.topic.has_value() && matcher.contains(*text.topic)) ||
                                 (text.alias.has_value() && matcher.contains(*text.alias));
            if (!matches)
            {
                continue;
            }
        }

        auto const offset = selected++;
        if (!may_be_in_page)
        {
            continue;
        }
        if (taken == page_size)
        {
            page_closed = true;
            continue;
        }
        auto entry = room_entry_json(store, room, text, room_type);
        if (!entry.has_value())
        {
            next_offset = offset + 1U;
            continue;
        }
        if (taken > 0U && chunk.size() + entry->size() + 1U > max_page_bytes)
        {
            page_closed = true;
            continue;
        }
        if (taken > 0U)
        {
            chunk += ',';
        }
        chunk += *entry;
        ++taken;
        next_offset = offset + 1U;
    }

    // Keys in canonical order. The paging tokens are decimal digits and need no escaping.
    auto body = std::string{R"({"chunk":[)"};
    body += chunk;
    body += ']';
    if (next_offset < selected)
    {
        // Spec: "The absence of this token means there are no more results to fetch".
        body += R"(,"next_batch":")" + std::to_string(next_offset) + '"';
    }
    // Spec: "The absence of this token means there are no results before this batch, i.e. this is the
    // first batch." A `since` past the end has the last page before it.
    auto const start = std::min(since_offset, selected);
    if (start > 0U)
    {
        body += R"(,"prev_batch":")" + std::to_string(start > page_size ? start - page_size : 0U) + '"';
    }
    body += R"(,"total_room_count_estimate":)" + std::to_string(selected) + '}';
    return body;
}

auto serve_federation_public_rooms(HomeserverRuntime& runtime, federation::PublicRoomsRequest const& request)
    -> std::string
{
    auto const guard = std::unique_lock<RuntimeMutex>{runtime.mutex};
    auto const max_page_size = static_cast<std::size_t>(runtime.config.server().client_api.max_public_rooms_page_size);
    auto const scope =
        public_rooms_scope(runtime.appservices, request.include_all_networks, request.third_party_instance_id);
    return public_rooms_response_json(runtime.database, request.filter,
                                      std::min(request.limit.value_or(max_page_size), max_page_size),
                                      request.since_offset, scope);
}

} // namespace merovingian::homeserver
