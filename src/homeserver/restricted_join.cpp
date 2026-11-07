// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/restricted_join.hpp"

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/database/ExaminedRows.hpp"
#include "merovingian/database/PersistentStateEvent.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/events/authorization.hpp"
#include "merovingian/homeserver/stored_room_version.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <algorithm>
#include <optional>
#include <string>
#include <unordered_map>
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

    [[nodiscard]] auto server_of(std::string_view user_id) noexcept -> std::string_view
    {
        auto const colon = user_id.find(':');
        return colon == std::string_view::npos ? std::string_view{} : user_id.substr(colon + 1U);
    }

    // One m.room_membership allow condition (client-server-api.md "Conditions"): the room whose
    // membership allows the join.
    struct Condition final
    {
        std::string room_id{};
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
            conditions.push_back({*room_text});
        }
        return conditions;
    }

    [[nodiscard]] auto refuse(RestrictedJoinVerdict verdict, std::string reason, RestrictedJoinWork work)
        -> RestrictedJoinDecision
    {
        return {verdict, {}, {}, std::move(reason), work};
    }

} // namespace

auto decide_restricted_join(database::PersistentStore const& store, std::string_view room_id, std::string_view user_id,
                            std::string_view our_server, std::string_view named_authoriser) -> RestrictedJoinDecision
{
    // F-19: every read below is a lookup by key in the state index (ADR-0344), a walk of one room's
    // own rows, or an event found by ID in its room. Nothing scans the state or the events of every
    // room, so a make_join pays for this room and the rooms its join rule names, not for the server.
    auto work = RestrictedJoinWork{};
    auto const current_state_id = [&store](std::string_view in_room, std::string_view type,
                                           std::string_view state_key) -> std::string {
        return database::find_current_state_event_id(store, in_room, type, state_key).value_or(std::string{});
    };
    // The stored event `event_id` of `in_room`, parsed; null when it is absent or not JSON.
    auto const load_event = [&store, &work](std::string_view in_room,
                                            std::string const& event_id) -> canonicaljson::Value {
        if (event_id.empty())
        {
            return canonicaljson::Value{};
        }
        auto const found = store.events.find_in_room(in_room, event_id);
        if (found == store.events.end())
        {
            return canonicaljson::Value{};
        }
        ++work.events_parsed;
        auto parsed = canonicaljson::parse_lossless(found->json);
        return parsed.error == canonicaljson::ParseError::none ? std::move(parsed.value) : canonicaljson::Value{};
    };
    // The event IDs of `in_room`'s member rows for users of this server, in storage order.
    auto const local_member_rows = [&](std::string_view in_room, std::string_view only_user) {
        auto rows = std::vector<std::pair<std::string, std::string>>{};
        database::for_each_room_state_row(store, in_room, [&](database::PersistentStateEvent const& state) {
            ++work.state_rows_visited;
            if (state.event_id.empty() || state.event_type != "m.room.member" ||
                server_of(state.state_key) != our_server || (!only_user.empty() && state.state_key != only_user))
            {
                return;
            }
            rows.emplace_back(state.state_key, state.event_id);
        });
        return rows;
    };

    auto const create_id = current_state_id(room_id, "m.room.create", {});
    if (create_id.empty())
    {
        return refuse(RestrictedJoinVerdict::unable_to_authorise, "this server holds no state for the room", work);
    }
    auto const create = load_event(room_id, create_id);
    // ADR-0179: the version a create event declares, through the one accessor.
    auto const* create_object = std::get_if<canonicaljson::Object>(&create.storage());
    auto const* policy = rooms::find_room_version_policy(
        create_object == nullptr ? std::string{"1"} : declared_room_version(*create_object));
    if (policy == nullptr)
    {
        return refuse(RestrictedJoinVerdict::forbidden, "the room's version is not supported", work);
    }
    auto const join_rules = load_event(room_id, current_state_id(room_id, "m.room.join_rules", {}));
    auto const join_rule = content_string(join_rules, "join_rule");
    auto const restricted = (join_rule == "restricted" && policy->restricted_join_rule) ||
                            (join_rule == "knock_restricted" && policy->knock_restricted_join_rule);
    if (!restricted)
    {
        return {RestrictedJoinVerdict::not_restricted, {}, {}, {}, work};
    }
    auto const target_membership =
        content_string(load_event(room_id, current_state_id(room_id, "m.room.member", user_id)), "membership");
    if (target_membership == "invite" || target_membership == "join")
    {
        return {RestrictedJoinVerdict::already_permitted, {}, {}, {}, work};
    }
    if (target_membership == "ban")
    {
        return refuse(RestrictedJoinVerdict::forbidden, "the user is banned from the room", work);
    }

    // The allow conditions, judged by this server's view of each named room, in order, until one
    // holds. A named room costs a few lookups and one walk of its own rows; the same room named
    // twice is read once. This runs under runtime.mutex and the list is room state another server
    // can write, so it is bounded by max_restricted_join_conditions (src/homeserver/AGENTS.md,
    // "Work under the runtime lock is bounded by the request").
    auto conditions = parse_conditions(join_rules);
    if (conditions.empty())
    {
        return refuse(RestrictedJoinVerdict::forbidden, "the room's join rules name no usable condition", work);
    }
    struct ConditionRoom final
    {
        bool known{false};
        std::string member_event_id{};
        std::vector<std::string> local_member_event_ids{};
    };
    auto condition_rooms = std::unordered_map<std::string, ConditionRoom>{};
    auto const condition_room = [&](std::string const& named_room) -> ConditionRoom const& {
        auto const cached = condition_rooms.find(named_room);
        if (cached != condition_rooms.end())
        {
            return cached->second;
        }
        auto view = ConditionRoom{};
        view.known = !current_state_id(named_room, "m.room.create", {}).empty();
        if (view.known)
        {
            view.member_event_id = current_state_id(named_room, "m.room.member", user_id);
            for (auto& [member_user, member_event_id] : local_member_rows(named_room, {}))
            {
                view.local_member_event_ids.push_back(std::move(member_event_id));
            }
        }
        return condition_rooms.emplace(named_room, std::move(view)).first->second;
    };
    auto const is_join = [&](std::string_view in_room, std::string const& event_id) {
        return content_string(load_event(in_room, event_id), "membership") == "join";
    };
    auto satisfied = false;
    auto any_unknown = false;
    for (auto const& condition : conditions)
    {
        auto const& view = condition_room(condition.room_id);
        // server-server-api.md "Restricted rooms": M_UNABLE_TO_AUTHORISE_JOIN
        // when the resident "does not have state information about rooms
        // required by the conditions". State kept after this server left a
        // room is not current: the user may have left or been banned there
        // since, so such a room cannot be validated either.
        if (!view.known || std::ranges::none_of(view.local_member_event_ids, [&](std::string const& event_id) {
                return is_join(condition.room_id, event_id);
            }))
        {
            any_unknown = true;
            continue;
        }
        if (!view.member_event_id.empty() && is_join(condition.room_id, view.member_event_id))
        {
            satisfied = true;
            break;
        }
    }
    if (!satisfied)
    {
        return any_unknown
                   ? refuse(RestrictedJoinVerdict::unable_to_authorise,
                            "this server cannot verify every condition of the room's join rules", work)
                   : refuse(RestrictedJoinVerdict::forbidden, "the user meets none of the room's conditions", work);
    }

    // rooms/v10.md 4.3.5.2 (v12.md 5.3.5.2): the authorising user must be a
    // joined member "with sufficient permission to invite other users".
    auto const power_levels = load_event(room_id, current_state_id(room_id, "m.room.power_levels", {}));
    auto const encoding = events::power_level_encoding(*policy);
    auto const invite_level = std::holds_alternative<std::nullptr_t>(power_levels.storage())
                                  ? std::int64_t{0}
                                  : events::extract_power_level_key(power_levels, "invite", 0, encoding);
    // A named authoriser (the send_join path) is one lookup; otherwise this room's local members.
    auto local_members = std::vector<std::pair<std::string, std::string>>{};
    if (named_authoriser.empty())
    {
        local_members = local_member_rows(room_id, {});
    }
    else if (server_of(named_authoriser) == our_server)
    {
        if (auto named_event_id = current_state_id(room_id, "m.room.member", named_authoriser); !named_event_id.empty())
        {
            local_members.emplace_back(std::string{named_authoriser}, std::move(named_event_id));
        }
    }
    std::ranges::sort(local_members);
    for (auto const& [member_user, member_event_id] : local_members)
    {
        if (!is_join(room_id, member_event_id))
        {
            continue;
        }
        if (events::effective_sender_power(power_levels, member_user, create, *policy) < invite_level)
        {
            continue;
        }
        return {RestrictedJoinVerdict::authorised, member_user, member_event_id, {}, work};
    }
    return refuse(RestrictedJoinVerdict::unable_to_grant,
                  named_authoriser.empty()
                      ? "no user of this server can authorise the join"
                      : "join_authorised_via_users_server is not a user of this server who can authorise the join",
                  work);
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
