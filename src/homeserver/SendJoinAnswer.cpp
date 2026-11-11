// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/SendJoinAnswer.hpp"

#include "merovingian/auth/Identity.hpp"
#include "merovingian/canonicaljson/ParseError.hpp"
#include "merovingian/canonicaljson/Parser.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/database/ExaminedRows.hpp"
#include "merovingian/database/PersistentStateEvent.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/KeyServerCache.hpp"
#include "merovingian/homeserver/LocalRoom.hpp"
#include "merovingian/homeserver/SendJoinAnswerEvents.hpp"
#include "merovingian/homeserver/SendJoinAnswerLimits.hpp"
#include "merovingian/homeserver/SendJoinAnswerPlan.hpp"
#include "merovingian/homeserver/SendJoinPlanBase.hpp"
#include "merovingian/homeserver/SendJoinPlanCache.hpp"
#include "merovingian/homeserver/SendJoinPlanStamp.hpp"
#include "merovingian/homeserver/WorkerIpcLimits.hpp"

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

    // The string `key` in the content of event `event_id`, if there is one.
    [[nodiscard]] auto event_content_text(database::PersistentStore const& store, std::string_view room_id,
                                          std::string_view event_id, std::string_view key) -> std::optional<std::string>
    {
        auto const event = store.events.find_in_room(room_id, event_id);
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
        return event_content_text(store, room_id, entry->event_id, key);
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

    // The two projections of an answer of `json_bytes` of events, `servers_bytes` of server names and `entries` array
    // entries. The body repeats each event once, with a comma; the frame carries each as an escaped string, and the
    // answer's other members under the same headroom.
    auto project_answer_sizes(SendJoinAnswerPlan& plan, std::uint64_t json_bytes, std::uint64_t servers_bytes,
                              std::uint64_t entries) noexcept -> void
    {
        plan.projected_body_bytes =
            saturating_add(saturating_add(json_bytes, servers_bytes), saturating_add(entries, answer_headroom_bytes));
        auto const frame_payload = saturating_add(json_bytes, servers_bytes);
        plan.projected_frame_bytes = saturating_add(
            saturating_add(frame_payload > std::numeric_limits<std::uint64_t>::max() / frame_escape_multiplier
                               ? std::numeric_limits<std::uint64_t>::max()
                               : frame_payload * frame_escape_multiplier,
                           entries * frame_entry_overhead_bytes),
            saturating_add(answer_headroom_bytes, answer_headroom_bytes));
    }

    // What a cached base must have been built from. Nothing when the store's state index cannot be trusted, since
    // the row count then says nothing about the room.
    [[nodiscard]] auto plan_stamp(HomeserverRuntime const& runtime, std::string_view room_id,
                                  SendJoinAnswerLimits const& limits) -> std::optional<SendJoinPlanStamp>
    {
        auto const& store = runtime.database.persistent_store;
        if (store.state_indexed_rows != store.state.size())
        {
            return std::nullopt;
        }
        auto stamp = SendJoinPlanStamp{};
        stamp.state_revision = database::room_state_revision(store, room_id);
        if (auto const rows = store.state_room_index.find(std::string{room_id}); rows != store.state_room_index.end())
        {
            stamp.state_rows = rows->second.size();
        }
        if (auto const* const room = find_local_room(runtime.database, room_id); room != nullptr)
        {
            stamp.roster_size = room->members.size();
        }
        stamp.max_body_bytes = limits.max_body_bytes;
        stamp.max_frame_bytes = limits.max_frame_bytes;
        return stamp;
    }

    // The room-wide part of the answer: one pass over the room's state and one walk of its auth DAG, for nobody in
    // particular. Everything `derive_plan` adds or takes away is at most one event from each list and the events a
    // request names, so an answer whose smallest possible size cannot fit is settled here, for every request.
    [[nodiscard]] auto build_plan_base(HomeserverRuntime const& runtime, std::string_view room_id, bool omit_members,
                                       SendJoinAnswerLimits const& limits) -> SendJoinPlanBase
    {
        auto const& store = runtime.database.persistent_store;
        auto const* const room = find_local_room(runtime.database, room_id);
        auto const state = current_room_state_entries(store, room_id);
        auto base = SendJoinPlanBase{};
        base.omit_members = omit_members;
        base.room_on_roster = room != nullptr;

        auto first_members = std::unordered_set<std::string_view>{};
        if (omit_members && room != nullptr)
        {
            for (auto const& member : room->members)
            {
                if (base.first_members.size() > max_send_join_heroes)
                {
                    break;
                }
                base.first_members.emplace_back(member);
                first_members.insert(member);
            }
            for (auto const& member : room->members)
            {
                auto server = std::string{auth::user_id_server_name(member)};
                if (server.empty())
                {
                    continue;
                }
                auto const [count, first_seen] = base.server_members.try_emplace(server, std::size_t{0U});
                ++count->second;
                if (first_seen)
                {
                    base.servers_bytes = saturating_add(base.servers_bytes, server.size());
                    base.servers.push_back(std::move(server));
                }
            }
        }
        for (auto const& entry : state)
        {
            if (omit_members && entry.event_type == "m.room.member")
            {
                ++base.omitted_members;
                if (first_members.contains(entry.state_key))
                {
                    base.hero_candidates.emplace_back(entry.state_key, entry.event_id);
                }
                continue;
            }
            base.state_event_ids.push_back(entry.event_id);
        }
        if (omit_members)
        {
            base.room_is_named = state_event_sets_text(store, room_id, state, "m.room.name", "name") ||
                                 state_event_sets_text(store, room_id, state, "m.room.canonical_alias", "alias");
        }

        auto queue = std::vector<std::string>{};
        auto const visit = [&base, &queue](std::string const& id) {
            if (!id.empty() && base.known.emplace(id, 0U).second)
            {
                queue.push_back(id);
            }
        };
        for (auto const& id : base.state_event_ids)
        {
            visit(id);
        }
        for (auto cursor = std::size_t{0U}; cursor < queue.size(); ++cursor)
        {
            auto const id = queue[cursor];
            auto const event = store.events.find_in_room(room_id, id);
            if (event == store.events.end())
            {
                base.missing.push_back(id);
                continue;
            }
            base.known[id] = event->json.size();
            for (auto const& auth_id : event->auth_event_ids)
            {
                base.cited.insert(auth_id);
                visit(auth_id);
            }
        }

        auto largest_state_event = std::uint64_t{0U};
        auto in_state = std::unordered_set<std::string_view>{};
        for (auto const& id : base.state_event_ids)
        {
            auto const size = base.known[id];
            if (omit_members)
            {
                in_state.insert(id);
            }
            if (size != 0U)
            {
                base.state_bytes = saturating_add(base.state_bytes, size);
                ++base.state_entries;
                largest_state_event = std::max(largest_state_event, size);
            }
        }
        for (auto const& id : queue)
        {
            auto const size = base.known[id];
            if (size != 0U && !in_state.contains(id))
            {
                base.chain_event_ids.push_back(id);
                base.chain_bytes = saturating_add(base.chain_bytes, size);
                ++base.chain_entries;
            }
        }

        // Without omit_members a resend takes its own join out of both lists; with it, a hero moves from the chain to
        // the state, which changes neither total, and everything else only adds.
        auto const removable = omit_members ? std::uint64_t{0U} : 2U * largest_state_event;
        auto const total_bytes = saturating_add(base.state_bytes, base.chain_bytes);
        auto const least_bytes = total_bytes > removable ? total_bytes - removable : 0U;
        auto const total_entries = saturating_add(base.state_entries, base.chain_entries);
        auto const least_entries = total_entries > 2U ? total_entries - 2U : 0U;
        auto least = SendJoinAnswerPlan{};
        project_answer_sizes(least, least_bytes, 0U, least_entries);
        if (send_join_answer_fits(least, limits))
        {
            return base;
        }
        auto verdict = SendJoinPlanBase{};
        verdict.omit_members = omit_members;
        verdict.sizes_only = true;
        verdict.state_bytes = least_bytes;
        verdict.state_entries = least_entries;
        return verdict;
    }

    // One request's plan from the room-wide base, by looking only at what the request changes. The result holds the
    // same IDs as `plan_send_join_answer` over the same state. Only the order of the auth chain can differ: the
    // base's walk starts from the state alone. Unlike that function it leaves the lists empty for an answer that does
    // not fit, which is then refused.
    [[nodiscard]] auto derive_plan(HomeserverRuntime const& runtime, SendJoinPlanBase const& base,
                                   std::string_view room_id, std::string_view joining_user,
                                   std::optional<SendJoinResend> const& resend,
                                   std::span<std::string const> join_auth_event_ids, SendJoinAnswerLimits const& limits)
        -> SendJoinAnswerPlan
    {
        auto plan = SendJoinAnswerPlan{};
        if (base.sizes_only)
        {
            project_answer_sizes(plan, base.state_bytes, 0U, base.state_entries);
            return plan;
        }
        auto const& store = runtime.database.persistent_store;
        auto const own_row = database::find_current_state_event_id(store, room_id, "m.room.member", joining_user);
        // resent_send_join_state: the joiner's row goes back only where the join itself is the current row.
        auto const swapped = resend.has_value() && own_row == resend->join_event_id;
        auto const before_id = swapped ? std::string_view{resend->before_event_id} : std::string_view{};
        auto const join_id = swapped ? std::string_view{resend->join_event_id} : std::string_view{};

        auto const size_of = [&base, &store, room_id](std::string const& id) -> std::uint64_t {
            if (auto const known = base.known.find(id); known != base.known.end())
            {
                return known->second;
            }
            auto const event = store.events.find_in_room(room_id, id);
            return event == store.events.end() ? 0U : event->json.size();
        };

        auto heroes = std::vector<std::string>{};
        auto omitted = base.omitted_members;
        if (base.omit_members)
        {
            if (swapped)
            {
                omitted = omitted - 1U + (before_id.empty() ? 0U : 1U);
            }
            if (omitted > 0U && base.room_on_roster && !base.room_is_named)
            {
                auto chosen = std::unordered_set<std::string_view>{};
                for (auto const& member : base.first_members)
                {
                    if (chosen.size() < max_send_join_heroes && member != joining_user)
                    {
                        chosen.insert(member);
                    }
                }
                for (auto const& [user, event_id] : base.hero_candidates)
                {
                    if (chosen.contains(user))
                    {
                        heroes.push_back(event_id);
                    }
                }
            }
            plan.members_omitted = omitted > heroes.size();
        }

        // What the request adds to the walk: its join's auth events, and the events it puts in the state.
        auto extra = std::unordered_map<std::string, std::uint64_t>{};
        auto queue = std::vector<std::string>{};
        auto const visit = [&base, &extra, &queue](std::string const& id) {
            if (!id.empty() && !base.known.contains(id) && extra.emplace(id, 0U).second)
            {
                queue.push_back(id);
            }
        };
        for (auto const& id : heroes)
        {
            visit(id);
        }
        if (!base.omit_members && !before_id.empty())
        {
            visit(std::string{before_id});
        }
        for (auto const& id : join_auth_event_ids)
        {
            visit(id);
        }
        auto join_cited = !join_id.empty() && base.cited.contains(std::string{join_id});
        for (auto cursor = std::size_t{0U}; cursor < queue.size(); ++cursor)
        {
            auto const id = queue[cursor];
            auto const event = store.events.find_in_room(room_id, id);
            if (event == store.events.end())
            {
                continue;
            }
            extra[id] = event->json.size();
            for (auto const& auth_id : event->auth_event_ids)
            {
                join_cited = join_cited || (!join_id.empty() && auth_id == join_id);
                visit(auth_id);
            }
        }

        auto state_bytes = base.state_bytes;
        auto state_entries = base.state_entries;
        auto chain_bytes = base.chain_bytes;
        auto chain_entries = base.chain_entries;
        // Without omit_members the join is a state event of the base and so in its chain. Out of the state, it stays
        // in the chain only if an event there names it; what it cites is still reached, from the join's auth events.
        auto const join_leaves_chain = !base.omit_members && swapped && !join_cited;
        if (!base.omit_members && swapped)
        {
            if (auto const size = size_of(resend->join_event_id); size != 0U)
            {
                state_bytes -= size;
                --state_entries;
                if (join_leaves_chain)
                {
                    chain_bytes -= size;
                    --chain_entries;
                }
            }
            if (!before_id.empty())
            {
                if (auto const size = size_of(resend->before_event_id); size != 0U)
                {
                    state_bytes = saturating_add(state_bytes, size);
                    ++state_entries;
                }
            }
        }
        for (auto const& id : heroes)
        {
            auto const size = size_of(id);
            if (size == 0U)
            {
                continue;
            }
            state_bytes = saturating_add(state_bytes, size);
            ++state_entries;
            if (base.known.contains(id))
            {
                chain_bytes -= size;
                --chain_entries;
            }
        }
        auto const is_hero = [&heroes](std::string const& id) {
            return std::ranges::find(heroes, id) != heroes.end();
        };
        for (auto const& id : queue)
        {
            if (auto const size = extra[id]; size != 0U && !is_hero(id))
            {
                chain_bytes = saturating_add(chain_bytes, size);
                ++chain_entries;
            }
        }

        // The joiner counts among the servers only if the answer's state has them joined already.
        auto not_counted_server = std::string{};
        auto servers_bytes = std::uint64_t{0U};
        auto servers_count = std::size_t{0U};
        if (plan.members_omitted && base.room_on_roster)
        {
            auto const joined_id = swapped ? std::optional<std::string>{resend->before_event_id} : own_row;
            auto const joined_before = joined_id.has_value() && !joined_id->empty() &&
                                       event_content_text(store, room_id, *joined_id, "membership") == "join";
            auto const* const room = find_local_room(runtime.database, room_id);
            servers_bytes = base.servers_bytes;
            servers_count = base.servers.size();
            if (!joined_before && room != nullptr && room->members.contains(joining_user))
            {
                auto const server = std::string{auth::user_id_server_name(joining_user)};
                if (auto const held = base.server_members.find(server);
                    held != base.server_members.end() && held->second == 1U)
                {
                    not_counted_server = server;
                    servers_bytes -= server.size();
                    --servers_count;
                }
            }
        }

        auto const json_bytes = saturating_add(state_bytes, chain_bytes);
        auto const entries = saturating_add(state_entries, chain_entries);
        plan.event_count = static_cast<std::size_t>(entries);
        plan.event_json_bytes = json_bytes;
        project_answer_sizes(plan, json_bytes, servers_bytes, saturating_add(entries, servers_count));
        if (!send_join_answer_fits(plan, limits))
        {
            return plan;
        }

        plan.state_event_ids.reserve(base.state_event_ids.size() + heroes.size() + 1U);
        for (auto const& id : base.state_event_ids)
        {
            if (base.omit_members || id != join_id)
            {
                plan.state_event_ids.push_back(id);
            }
        }
        if (!base.omit_members && !before_id.empty())
        {
            plan.state_event_ids.emplace_back(before_id);
        }
        plan.state_event_ids.insert(plan.state_event_ids.end(), heroes.begin(), heroes.end());
        plan.auth_chain_event_ids.reserve(base.chain_event_ids.size() + queue.size());
        for (auto const& id : base.chain_event_ids)
        {
            if (!(join_leaves_chain && id == join_id) && !is_hero(id))
            {
                plan.auth_chain_event_ids.push_back(id);
            }
        }
        for (auto const& id : queue)
        {
            if (extra[id] != 0U && !is_hero(id))
            {
                plan.auth_chain_event_ids.push_back(id);
            }
        }
        if (plan.members_omitted && base.room_on_roster)
        {
            plan.servers_in_room.reserve(servers_count);
            for (auto const& server : base.servers)
            {
                if (server != not_counted_server)
                {
                    plan.servers_in_room.push_back(server);
                }
            }
        }
        return plan;
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
    project_answer_sizes(plan, json_bytes, servers_bytes, entries);
    return plan;
}

auto plan_send_join_answer_cached(HomeserverRuntime const& runtime, std::string_view room_id,
                                  std::string_view joining_user, std::optional<SendJoinResend> const& resend,
                                  std::span<std::string const> join_auth_event_ids, bool omit_members,
                                  SendJoinAnswerLimits const& limits) -> SendJoinAnswerPlan
{
    auto const& store = runtime.database.persistent_store;
    auto const stamp = plan_stamp(runtime, room_id, limits);
    if (!stamp.has_value())
    {
        auto state = current_room_state_entries(store, room_id);
        if (resend.has_value())
        {
            auto before = std::vector<database::PersistentStateGroupStateEntry>{};
            if (!resend->before_event_id.empty())
            {
                before.push_back({{}, "m.room.member", std::string{joining_user}, resend->before_event_id});
            }
            state = resent_send_join_state(store, room_id, joining_user, resend->join_event_id, before);
        }
        return plan_send_join_answer(runtime, room_id, joining_user, state, join_auth_event_ids, omit_members);
    }
    auto plan = SendJoinAnswerPlan{};
    runtime.send_join_plan_cache->with_base(
        room_id, omit_members, *stamp,
        // An event a base found missing may have arrived since, without any state changing.
        [&store, room_id](SendJoinPlanBase const& base) {
            return std::ranges::none_of(base.missing, [&store, room_id](std::string const& id) {
                return store.events.find_in_room(room_id, id) != store.events.end();
            });
        },
        [&runtime, room_id, omit_members, &limits] {
            return build_plan_base(runtime, room_id, omit_members, limits);
        },
        [&](SendJoinPlanBase const& base) {
            plan = derive_plan(runtime, base, room_id, joining_user, resend, join_auth_event_ids, limits);
        });
    return plan;
}

auto send_join_answer_known_not_to_fit(HomeserverRuntime const& runtime, std::string_view room_id, bool omit_members,
                                       SendJoinAnswerLimits const& limits) -> bool
{
    auto const stamp = plan_stamp(runtime, room_id, limits);
    return stamp.has_value() && runtime.send_join_plan_cache->known_not_to_fit(room_id, omit_members, *stamp);
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
