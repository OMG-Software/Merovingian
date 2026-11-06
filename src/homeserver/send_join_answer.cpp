// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/send_join_answer.hpp"

#include "merovingian/auth/identity.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/database/ExaminedRows.hpp"
#include "merovingian/database/PersistentStateEvent.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/KeyServerCache.hpp"
#include "merovingian/homeserver/LocalRoom.hpp"
#include "merovingian/homeserver/worker_ipc_limits.hpp"

#include <algorithm>
#include <limits>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <variant>

namespace merovingian::homeserver
{

namespace
{

    // Room left in the body and the frame for what is not an event: the `event` member (a PDU is
    // at most 64 KiB), the room version, `members_omitted` and the surrounding JSON.
    constexpr auto answer_headroom_bytes = std::uint64_t{256U * 1024U};
    // A string in a JSON frame at most doubles: a byte of canonical JSON is escaped to two at
    // worst (`"` and `\`), and canonical JSON holds no raw control byte.
    constexpr auto frame_escape_multiplier = std::uint64_t{2U};
    // Per array entry of a frame: the string's two quotes and the comma.
    constexpr auto frame_entry_overhead_bytes = std::uint64_t{3U};

    [[nodiscard]] auto saturating_add(std::uint64_t lhs, std::uint64_t rhs) noexcept -> std::uint64_t
    {
        return rhs > std::numeric_limits<std::uint64_t>::max() - lhs ? std::numeric_limits<std::uint64_t>::max()
                                                                     : lhs + rhs;
    }

    // The string `key` in the content of the `type` event for `state_key` in `state`, if there is one.
    [[nodiscard]] auto state_event_text(database::PersistentStore const& store, std::string_view room_id,
                                        std::vector<database::PersistentStateGroupStateEntry> const& state,
                                        std::string_view type, std::string_view state_key, std::string_view key)
        -> std::optional<std::string>
    {
        auto const entry =
            std::ranges::find_if(state, [type, state_key](database::PersistentStateGroupStateEntry const& current) {
                return current.event_type == type && current.state_key == state_key;
            });
        if (entry == state.end())
        {
            return std::nullopt;
        }
        auto const event = store.events.find_in_room(room_id, entry->event_id);
        if (event == store.events.end())
        {
            return std::nullopt;
        }
        auto const parsed = canonicaljson::parse_lossless(event->json);
        auto const* root = parsed.error == canonicaljson::ParseError::none
                               ? std::get_if<canonicaljson::Object>(&parsed.value.storage())
                               : nullptr;
        if (root == nullptr)
        {
            return std::nullopt;
        }
        for (auto const& member : *root)
        {
            if (member.key != "content")
            {
                continue;
            }
            auto const* content = std::get_if<canonicaljson::Object>(&member.value->storage());
            if (content == nullptr)
            {
                return std::nullopt;
            }
            for (auto const& field : *content)
            {
                if (field.key == key)
                {
                    auto const* text = std::get_if<std::string>(&field.value->storage());
                    return text == nullptr ? std::nullopt : std::optional<std::string>{*text};
                }
            }
        }
        return std::nullopt;
    }

    // Whether the room's current `type` event (state key "") has a non-empty string `key` in its
    // content: client-server-api.md treats an empty name or alias as unset.
    [[nodiscard]] auto state_event_sets_text(database::PersistentStore const& store, std::string_view room_id,
                                             std::vector<database::PersistentStateGroupStateEntry> const& state,
                                             std::string_view type, std::string_view key) -> bool
    {
        auto const text = state_event_text(store, room_id, state, type, {}, key);
        return text.has_value() && !text->empty();
    }

    // The members whose events a reduced state still carries so the joiner can name the room:
    // the first `max_send_join_heroes` joined members other than the joiner, in roster order.
    [[nodiscard]] auto hero_member_event_ids(LocalRoom const& room, std::string_view joining_user,
                                             std::vector<database::PersistentStateGroupStateEntry> const& state)
        -> std::vector<std::string>
    {
        auto heroes = std::unordered_set<std::string_view>{};
        for (auto const& member : room.members)
        {
            if (heroes.size() == max_send_join_heroes)
            {
                break;
            }
            if (member != joining_user)
            {
                heroes.insert(member);
            }
        }
        auto ids = std::vector<std::string>{};
        for (auto const& entry : state)
        {
            if (entry.event_type == "m.room.member" && heroes.contains(entry.state_key) && !entry.event_id.empty())
            {
                ids.push_back(entry.event_id);
            }
        }
        return ids;
    }

    // The servers of the roster's members, leaving out `not_counted`.
    [[nodiscard]] auto servers_with_joined_members(LocalRoom const& room, std::string_view not_counted)
        -> std::vector<std::string>
    {
        auto seen = std::unordered_set<std::string>{};
        auto servers = std::vector<std::string>{};
        for (auto const& member : room.members)
        {
            if (member == not_counted)
            {
                continue;
            }
            auto const server = auth::user_id_server_name(member);
            if (!server.empty() && seen.emplace(server).second)
            {
                servers.emplace_back(server);
            }
        }
        return servers;
    }

} // namespace

auto send_join_answer_limits(config::Config const& config) -> SendJoinAnswerLimits
{
    auto limits = SendJoinAnswerLimits{};
    auto const join_response_max_size = config::parse_size_limit(config.security().federation.join_response_max_size);
    limits.max_body_bytes =
        join_response_max_size.valid ? join_response_max_size.bytes : std::numeric_limits<std::uint64_t>::max();
    limits.max_frame_bytes = worker_ipc_frame_bytes(config);
    return limits;
}

auto current_room_state_entries(database::PersistentStore const& store, std::string_view room_id)
    -> std::vector<database::PersistentStateGroupStateEntry>
{
    auto entries = std::vector<database::PersistentStateGroupStateEntry>{};
    database::for_each_room_state_row(store, room_id, [&entries](database::PersistentStateEvent const& row) {
        if (!row.event_id.empty())
        {
            entries.push_back({{}, row.event_type, row.state_key, row.event_id});
        }
    });
    return entries;
}

auto resent_send_join_state(database::PersistentStore const& store, std::string_view room_id,
                            std::string_view joining_user, std::string_view join_event_id,
                            std::vector<database::PersistentStateGroupStateEntry> const& state_before_join)
    -> std::vector<database::PersistentStateGroupStateEntry>
{
    auto const is_joiners_membership = [joining_user](database::PersistentStateGroupStateEntry const& entry) {
        return entry.event_type == "m.room.member" && entry.state_key == joining_user;
    };
    auto state = current_room_state_entries(store, room_id);
    auto const own = std::ranges::find_if(state, is_joiners_membership);
    if (own == state.end() || own->event_id != join_event_id)
    {
        return state;
    }
    state.erase(own);
    auto const before = std::ranges::find_if(state_before_join, is_joiners_membership);
    if (before != state_before_join.end() && !before->event_id.empty())
    {
        state.push_back(*before);
    }
    return state;
}

auto plan_send_join_answer(HomeserverRuntime const& runtime, std::string_view room_id, std::string_view joining_user,
                           std::vector<database::PersistentStateGroupStateEntry> const& state,
                           std::span<std::string const> join_auth_event_ids, bool omit_members) -> SendJoinAnswerPlan
{
    auto const& store = runtime.database.persistent_store;
    auto plan = SendJoinAnswerPlan{};
    auto const room_it = std::ranges::find_if(runtime.database.rooms, [&room_id](LocalRoom const& room) {
        return room.room_id == room_id;
    });

    // The state, once. A reduced answer leaves membership events out.
    auto omitted_members = std::size_t{0U};
    for (auto const& entry : state)
    {
        if (entry.event_id.empty())
        {
            continue;
        }
        if (omit_members && entry.event_type == "m.room.member")
        {
            ++omitted_members;
            continue;
        }
        plan.state_event_ids.push_back(entry.event_id);
    }
    if (omitted_members > 0U)
    {
        // With no name and no alias the joiner needs the heroes' membership events to name the
        // room ("should" in the spec); they go back into the state.
        auto heroes_returned = std::size_t{0U};
        if (room_it != runtime.database.rooms.end() &&
            !state_event_sets_text(store, room_id, state, "m.room.name", "name") &&
            !state_event_sets_text(store, room_id, state, "m.room.canonical_alias", "alias"))
        {
            for (auto& id : hero_member_event_ids(*room_it, joining_user, state))
            {
                plan.state_event_ids.push_back(std::move(id));
                ++heroes_returned;
            }
        }
        // `members_omitted` is true if m.room.member events have been omitted from `state`.
        plan.members_omitted = omitted_members > heroes_returned;
        if (plan.members_omitted && room_it != runtime.database.rooms.end())
        {
            // "Before the join": a join already stored has put the joiner on the roster, so the
            // joiner counts only if `state` has them joined already.
            auto const joined_before =
                state_event_text(store, room_id, state, "m.room.member", joining_user, "membership") == "join";
            plan.servers_in_room =
                servers_with_joined_members(*room_it, joined_before ? std::string_view{} : joining_user);
        }
    }

    // The auth chain: a breadth-first walk of auth_events from the returned state and from the
    // join's own auth events. `known` holds each visited event's JSON size, 0 for one this
    // server holds no JSON for.
    auto known = std::unordered_map<std::string, std::uint64_t>{};
    auto queue = std::vector<std::string>{};
    auto const visit = [&](std::string const& id) {
        if (!id.empty() && known.emplace(id, 0U).second)
        {
            queue.push_back(id);
        }
    };
    for (auto const& id : plan.state_event_ids)
    {
        visit(id);
    }
    for (auto const& id : join_auth_event_ids)
    {
        visit(id);
    }
    for (auto cursor = std::size_t{0U}; cursor < queue.size(); ++cursor)
    {
        auto const id = queue[cursor];
        auto const event = store.events.find_in_room(room_id, id);
        if (event == store.events.end())
        {
            continue;
        }
        known[id] = event->json.size();
        for (auto const& auth_id : event->auth_event_ids)
        {
            visit(auth_id);
        }
    }

    auto const returned_in_state = [&] {
        auto ids = std::unordered_set<std::string>{};
        if (omit_members)
        {
            ids.insert(plan.state_event_ids.begin(), plan.state_event_ids.end());
        }
        return ids;
    }();
    auto json_bytes = std::uint64_t{0U};
    auto servers_bytes = std::uint64_t{0U};
    auto entries = std::uint64_t{0U};
    for (auto const& id : plan.state_event_ids)
    {
        if (auto const size = known[id]; size != 0U)
        {
            json_bytes = saturating_add(json_bytes, size);
            ++entries;
        }
    }
    for (auto const& id : queue)
    {
        auto const size = known[id];
        if (size == 0U || returned_in_state.contains(id))
        {
            continue;
        }
        plan.auth_chain_event_ids.push_back(id);
        json_bytes = saturating_add(json_bytes, size);
        ++entries;
    }
    for (auto const& server : plan.servers_in_room)
    {
        servers_bytes = saturating_add(servers_bytes, server.size());
    }
    plan.event_count = static_cast<std::size_t>(entries);
    entries = saturating_add(entries, plan.servers_in_room.size());
    plan.event_json_bytes = json_bytes;
    // The body repeats each event once, with a comma; the frame carries each as an escaped
    // string, and the answer's other members under the same headroom.
    plan.projected_body_bytes =
        saturating_add(saturating_add(json_bytes, servers_bytes), saturating_add(entries, answer_headroom_bytes));
    auto const frame_payload = saturating_add(json_bytes, servers_bytes);
    plan.projected_frame_bytes = saturating_add(
        saturating_add(frame_payload > std::numeric_limits<std::uint64_t>::max() / frame_escape_multiplier
                           ? std::numeric_limits<std::uint64_t>::max()
                           : frame_payload * frame_escape_multiplier,
                       entries * frame_entry_overhead_bytes),
        saturating_add(answer_headroom_bytes, answer_headroom_bytes));
    return plan;
}

auto send_join_answer_fits(SendJoinAnswerPlan const& plan, SendJoinAnswerLimits const& limits) noexcept -> bool
{
    return plan.projected_body_bytes <= limits.max_body_bytes && plan.projected_frame_bytes <= limits.max_frame_bytes;
}

auto collect_send_join_answer(database::PersistentStore const& store, std::string_view room_id,
                              SendJoinAnswerPlan const& plan) -> SendJoinAnswerEvents
{
    auto events = SendJoinAnswerEvents{};
    auto const copy_into = [&](std::vector<std::string> const& ids, std::vector<std::string>& out) {
        out.reserve(ids.size());
        for (auto const& id : ids)
        {
            auto const event = store.events.find_in_room(room_id, id);
            if (event != store.events.end() && !event->json.empty())
            {
                out.push_back(event->json);
            }
        }
    };
    copy_into(plan.state_event_ids, events.state_json);
    copy_into(plan.auth_chain_event_ids, events.auth_chain_json);
    return events;
}

} // namespace merovingian::homeserver
