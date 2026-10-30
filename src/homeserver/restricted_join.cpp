// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/restricted_join.hpp"

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/events/authorization.hpp"
#include "merovingian/homeserver/stored_room_version.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <algorithm>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

namespace merovingian::homeserver
{

namespace
{

    [[nodiscard]] auto member_of(canonicaljson::Object const& object, std::string_view key)
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

    [[nodiscard]] auto content_of(canonicaljson::Value const& event) -> canonicaljson::Object const*
    {
        auto const* root = std::get_if<canonicaljson::Object>(&event.storage());
        auto const* content = root == nullptr ? nullptr : member_of(*root, "content");
        return content == nullptr ? nullptr : std::get_if<canonicaljson::Object>(&content->storage());
    }

    [[nodiscard]] auto content_string(canonicaljson::Value const& event, std::string_view key) -> std::string
    {
        auto const* content = content_of(event);
        auto const* value = content == nullptr ? nullptr : member_of(*content, key);
        auto const* text = value == nullptr ? nullptr : std::get_if<std::string>(&value->storage());
        return text == nullptr ? std::string{} : *text;
    }

    // Parses the stored JSON of each wanted event, in one pass over the store.
    [[nodiscard]] auto load_events(database::PersistentStore const& store,
                                   std::unordered_set<std::string> const& wanted)
        -> std::unordered_map<std::string, canonicaljson::Value>
    {
        auto loaded = std::unordered_map<std::string, canonicaljson::Value>{};
        if (wanted.empty())
        {
            return loaded;
        }
        for (auto const& event : store.events)
        {
            if (!wanted.contains(event.event_id) || loaded.contains(event.event_id))
            {
                continue;
            }
            auto parsed = canonicaljson::parse_lossless(event.json);
            if (parsed.error == canonicaljson::ParseError::none)
            {
                loaded.emplace(event.event_id, std::move(parsed.value));
            }
        }
        return loaded;
    }

    [[nodiscard]] auto server_of(std::string_view user_id) noexcept -> std::string_view
    {
        auto const colon = user_id.find(':');
        return colon == std::string_view::npos ? std::string_view{} : user_id.substr(colon + 1U);
    }

    // One m.room_membership allow condition (client-server-api.md "Conditions").
    // It can be validated only from current state of its room, so only while
    // this server is resident there: `known` (its m.room.create is stored)
    // and a joined user of this server among `local_member_event_ids`.
    struct Condition final
    {
        std::string room_id{};
        bool known{false};
        std::string member_event_id{};
        std::vector<std::string> local_member_event_ids{};
    };

    [[nodiscard]] auto parse_conditions(canonicaljson::Value const& join_rules) -> std::vector<Condition>
    {
        auto conditions = std::vector<Condition>{};
        auto const* content = content_of(join_rules);
        auto const* allow = content == nullptr ? nullptr : member_of(*content, "allow");
        auto const* entries = allow == nullptr ? nullptr : std::get_if<canonicaljson::Array>(&allow->storage());
        if (entries == nullptr)
        {
            return conditions;
        }
        auto considered = std::size_t{0U};
        for (auto const& entry : *entries)
        {
            if (considered == max_restricted_join_conditions)
            {
                break;
            }
            ++considered;
            // "If no conditions are available, or none match the required
            // schema, then the joining server is considered to have failed all
            // conditions." An entry of another type or shape is skipped.
            auto const* object = std::get_if<canonicaljson::Object>(&entry.storage());
            auto const* type = object == nullptr ? nullptr : member_of(*object, "type");
            auto const* type_text = type == nullptr ? nullptr : std::get_if<std::string>(&type->storage());
            auto const* room = object == nullptr ? nullptr : member_of(*object, "room_id");
            auto const* room_text = room == nullptr ? nullptr : std::get_if<std::string>(&room->storage());
            if (type_text == nullptr || *type_text != "m.room_membership" || room_text == nullptr || room_text->empty())
            {
                continue;
            }
            conditions.push_back({*room_text, false, {}, {}});
        }
        return conditions;
    }

    [[nodiscard]] auto refuse(RestrictedJoinVerdict verdict, std::string reason) -> RestrictedJoinDecision
    {
        return {verdict, {}, {}, std::move(reason)};
    }

} // namespace

auto decide_restricted_join(database::PersistentStore const& store, std::string_view room_id, std::string_view user_id,
                            std::string_view our_server, std::string_view named_authoriser) -> RestrictedJoinDecision
{
    // The room's own state: create, join rules, power levels, the joining
    // user's membership, and every member event of this server's users.
    auto create_id = std::string{};
    auto join_rules_id = std::string{};
    auto power_levels_id = std::string{};
    auto target_member_id = std::string{};
    auto local_members = std::vector<std::pair<std::string, std::string>>{};
    for (auto const& state : store.state)
    {
        if (state.room_id != room_id || state.event_id.empty())
        {
            continue;
        }
        if (state.event_type == "m.room.create" && state.state_key.empty())
        {
            create_id = state.event_id;
        }
        else if (state.event_type == "m.room.join_rules" && state.state_key.empty())
        {
            join_rules_id = state.event_id;
        }
        else if (state.event_type == "m.room.power_levels" && state.state_key.empty())
        {
            power_levels_id = state.event_id;
        }
        else if (state.event_type == "m.room.member")
        {
            if (state.state_key == user_id)
            {
                target_member_id = state.event_id;
            }
            if (server_of(state.state_key) == our_server &&
                (named_authoriser.empty() || state.state_key == named_authoriser))
            {
                local_members.emplace_back(state.state_key, state.event_id);
            }
        }
    }
    if (create_id.empty())
    {
        return refuse(RestrictedJoinVerdict::unable_to_authorise, "this server holds no state for the room");
    }
    auto wanted = std::unordered_set<std::string>{create_id, join_rules_id, power_levels_id, target_member_id};
    wanted.erase(std::string{});
    auto room_events = load_events(store, wanted);
    auto const event_or_null = [&room_events](std::string const& id) -> canonicaljson::Value {
        auto const found = room_events.find(id);
        return found == room_events.end() ? canonicaljson::Value{} : found->second;
    };
    auto const create = event_or_null(create_id);
    // ADR-0179: the version a create event declares, through the one accessor.
    auto const* create_object = std::get_if<canonicaljson::Object>(&create.storage());
    auto const* policy = rooms::find_room_version_policy(
        create_object == nullptr ? std::string{"1"} : declared_room_version(*create_object));
    if (policy == nullptr)
    {
        return refuse(RestrictedJoinVerdict::forbidden, "the room's version is not supported");
    }
    auto const join_rules = event_or_null(join_rules_id);
    auto const join_rule = content_string(join_rules, "join_rule");
    auto const restricted = (join_rule == "restricted" && policy->restricted_join_rule) ||
                            (join_rule == "knock_restricted" && policy->knock_restricted_join_rule);
    if (!restricted)
    {
        return {RestrictedJoinVerdict::not_restricted, {}, {}, {}};
    }
    auto const target_membership = content_string(event_or_null(target_member_id), "membership");
    if (target_membership == "invite" || target_membership == "join")
    {
        return {RestrictedJoinVerdict::already_permitted, {}, {}, {}};
    }
    if (target_membership == "ban")
    {
        return refuse(RestrictedJoinVerdict::forbidden, "the user is banned from the room");
    }

    // The allow conditions, judged by this server's view of each named room.
    // This runs under runtime.mutex and the list is room state another server
    // can write, so the cost per state row must not grow with it: one pass
    // over store.state with one hash lookup per row, then one pass over
    // store.events for every member event needed below (src/homeserver/
    // AGENTS.md, "Work under the runtime lock is bounded by the request").
    auto conditions = parse_conditions(join_rules);
    if (conditions.empty())
    {
        return refuse(RestrictedJoinVerdict::forbidden, "the room's join rules name no usable condition");
    }
    auto conditions_by_room = std::unordered_map<std::string_view, std::vector<std::size_t>>{};
    for (auto index = std::size_t{0U}; index < conditions.size(); ++index)
    {
        conditions_by_room[conditions[index].room_id].push_back(index);
    }
    for (auto const& state : store.state)
    {
        if (state.event_id.empty())
        {
            continue;
        }
        auto const found = conditions_by_room.find(state.room_id);
        if (found == conditions_by_room.end())
        {
            continue;
        }
        auto const is_create = state.event_type == "m.room.create" && state.state_key.empty();
        auto const is_member = state.event_type == "m.room.member";
        if (!is_create && !is_member)
        {
            continue;
        }
        for (auto const index : found->second)
        {
            auto& condition = conditions[index];
            if (is_create)
            {
                condition.known = true;
                continue;
            }
            if (state.state_key == user_id)
            {
                condition.member_event_id = state.event_id;
            }
            if (server_of(state.state_key) == our_server)
            {
                condition.local_member_event_ids.push_back(state.event_id);
            }
        }
    }
    // Every member event read below, the authorising candidates' included, in
    // one pass over store.events.
    auto member_ids = std::unordered_set<std::string>{};
    for (auto const& condition : conditions)
    {
        if (!condition.known)
        {
            continue;
        }
        if (!condition.member_event_id.empty())
        {
            member_ids.insert(condition.member_event_id);
        }
        member_ids.insert(condition.local_member_event_ids.begin(), condition.local_member_event_ids.end());
    }
    for (auto const& [member_user, member_event_id] : local_members)
    {
        member_ids.insert(member_event_id);
    }
    auto const member_events = load_events(store, member_ids);
    auto const is_join = [&member_events](std::string const& event_id) {
        auto const member = member_events.find(event_id);
        return member != member_events.end() && content_string(member->second, "membership") == "join";
    };
    auto satisfied = false;
    auto any_unknown = false;
    for (auto const& condition : conditions)
    {
        // server-server-api.md "Restricted rooms": M_UNABLE_TO_AUTHORISE_JOIN
        // when the resident "does not have state information about rooms
        // required by the conditions". State kept after this server left a
        // room is not current: the user may have left or been banned there
        // since, so such a room cannot be validated either.
        if (!condition.known || std::ranges::none_of(condition.local_member_event_ids, is_join))
        {
            any_unknown = true;
            continue;
        }
        if (!condition.member_event_id.empty() && is_join(condition.member_event_id))
        {
            satisfied = true;
            break;
        }
    }
    if (!satisfied)
    {
        return any_unknown ? refuse(RestrictedJoinVerdict::unable_to_authorise,
                                    "this server cannot verify every condition of the room's join rules")
                           : refuse(RestrictedJoinVerdict::forbidden, "the user meets none of the room's conditions");
    }

    // rooms/v10.md 4.3.5.2 (v12.md 5.3.5.2): the authorising user must be a
    // joined member "with sufficient permission to invite other users".
    auto const power_levels = event_or_null(power_levels_id);
    auto const encoding = events::power_level_encoding(*policy);
    auto const invite_level = std::holds_alternative<std::nullptr_t>(power_levels.storage())
                                  ? std::int64_t{0}
                                  : events::extract_power_level_key(power_levels, "invite", 0, encoding);
    std::ranges::sort(local_members);
    for (auto const& [member_user, member_event_id] : local_members)
    {
        if (!is_join(member_event_id))
        {
            continue;
        }
        if (events::effective_sender_power(power_levels, member_user, create, *policy) < invite_level)
        {
            continue;
        }
        return {RestrictedJoinVerdict::authorised, member_user, member_event_id, {}};
    }
    return refuse(RestrictedJoinVerdict::unable_to_grant,
                  named_authoriser.empty()
                      ? "no user of this server can authorise the join"
                      : "join_authorised_via_users_server is not a user of this server who can authorise the join");
}

auto restricted_join_fallback_candidates(std::vector<std::string> const& via_servers,
                                         std::vector<std::string> const& resident_servers, std::string_view our_server,
                                         std::size_t max_candidates) -> std::vector<std::string>
{
    auto candidates = std::vector<std::string>{};
    for (auto const* list : {&via_servers, &resident_servers})
    {
        for (auto const& server : *list)
        {
            if (candidates.size() == max_candidates)
            {
                return candidates;
            }
            if (!server.empty() && server != our_server && std::ranges::find(candidates, server) == candidates.end())
            {
                candidates.push_back(server);
            }
        }
    }
    return candidates;
}

auto restricted_join_refusal_status(RestrictedJoinVerdict verdict) noexcept -> std::uint16_t
{
    switch (verdict)
    {
    case RestrictedJoinVerdict::unable_to_authorise:
    case RestrictedJoinVerdict::unable_to_grant:
        return 400U;
    case RestrictedJoinVerdict::forbidden:
        return 403U;
    case RestrictedJoinVerdict::not_restricted:
    case RestrictedJoinVerdict::already_permitted:
    case RestrictedJoinVerdict::authorised:
        return 200U;
    }
    return 403U;
}

auto restricted_join_refusal_errcode(RestrictedJoinVerdict verdict) noexcept -> std::string_view
{
    switch (verdict)
    {
    case RestrictedJoinVerdict::unable_to_authorise:
        return "M_UNABLE_TO_AUTHORISE_JOIN";
    case RestrictedJoinVerdict::unable_to_grant:
        return "M_UNABLE_TO_GRANT_JOIN";
    case RestrictedJoinVerdict::forbidden:
        return "M_FORBIDDEN";
    case RestrictedJoinVerdict::not_restricted:
    case RestrictedJoinVerdict::already_permitted:
    case RestrictedJoinVerdict::authorised:
        return {};
    }
    return "M_FORBIDDEN";
}

} // namespace merovingian::homeserver
