// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/push_badge_count.hpp"

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/homeserver/push_rule_unread_classifier.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/sync/read_markers.hpp"

#include <algorithm>
#include <functional>
#include <limits>
#include <map>
#include <optional>
#include <ranges>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace merovingian::homeserver
{
namespace
{

    // A visited event the user's rules notify for, waiting for its room's join start.
    struct Candidate final
    {
        std::uint64_t stream_ordering{0U};
        std::string thread_id{};
    };

    // What the walk has learnt about one joined room.
    struct BadgeRoom final
    {
        // Receipt positions, resolved before the walk; the user's own events add to `threads` as
        // the walk meets them.
        sync::ReadMarkers markers{};
        std::vector<std::pair<std::uint64_t, bool>> transitions{};
        std::vector<Candidate> candidates{};
        // The stream ordering on the user's membership row, rewritten on every membership event
        // they get (profile changes included), so at or after the start of the current join.
        std::uint64_t membership_row_ordering{0U};
        // Nothing the walk has still to visit can change the room's count.
        bool settled{false};
        // A non-join membership change has been met: the join start is pinned once the walk has
        // passed below it.
        bool met_non_join{false};
    };

    [[nodiscard]] auto has_member(canonicaljson::Object const& object, std::string_view key) noexcept -> bool
    {
        return std::ranges::any_of(object, [key](canonicaljson::ObjectMember const& member) {
            return member.key == key;
        });
    }

    // The thread a non-state event the user sent reads (read_markers_for, ADR-0170), or nullopt for
    // a state event, which reads nothing.
    [[nodiscard]] auto own_event_thread(database::PersistentStore const& store, database::PersistentEvent const& row)
        -> std::optional<std::string>
    {
        if (row.json.find("\"state_key\"") == std::string::npos &&
            row.json.find("\"m.relates_to\"") == std::string::npos)
        {
            return std::string{sync::main_thread_id};
        }
        auto const parsed = canonicaljson::parse_lossless(row.json);
        auto const* object = std::get_if<canonicaljson::Object>(&parsed.value.storage());
        if (parsed.error != canonicaljson::ParseError::none || object == nullptr || has_member(*object, "state_key"))
        {
            return std::nullopt;
        }
        return sync::event_thread_id(store, *object);
    }

} // namespace

auto count_push_badge(HomeserverRuntime const& runtime, std::string_view user_id, push::PushRuleset const& ruleset,
                      std::uint64_t row_budget) -> PushBadgeCount
{
    auto const& store = runtime.database.persistent_store;
    auto result = PushBadgeCount{};

    // Before the walk: the joined rooms, and each one's receipt positions. read_markers_for reads
    // m.read and m.read.private, at the stream ordering of the event each names in the room; a
    // receipt whose event is not stored there moves nothing.
    auto rooms = std::map<std::string, BadgeRoom, std::less<>>{};
    for (auto const& membership : store.memberships)
    {
        if (membership.user_id == user_id && membership.membership == "join")
        {
            rooms.try_emplace(membership.room_id).first->second.membership_row_ordering = membership.stream_ordering;
        }
    }
    ++result.table_walks;
    for (auto const& receipt : store.receipts)
    {
        auto const room = rooms.find(receipt.room_id);
        if (receipt.user_id != user_id || room == rooms.end() ||
            (receipt.receipt_type != "m.read" && receipt.receipt_type != "m.read.private"))
        {
            continue;
        }
        auto const event = store.events.find_in_room(receipt.room_id, receipt.event_id);
        if (event == store.events.end())
        {
            continue;
        }
        auto& markers = room->second.markers;
        auto& position = receipt.thread_id.empty() ? markers.unthreaded : markers.threads[receipt.thread_id];
        position = std::max(position, event->stream_ordering);
    }
    ++result.table_walks;

    auto const classifier = PushRuleUnreadClassifier{store, user_id, ruleset};
    auto unsettled = rooms.size();
    auto const settle = [&unsettled](BadgeRoom& room) {
        if (!room.settled)
        {
            room.settled = true;
            --unsettled;
        }
    };
    // Rooms that met a non-join membership change, by its stream ordering, highest first: each is
    // settled once the walk is below that ordering, when every transition at or above it is known.
    auto pinned = std::multimap<std::uint64_t, std::reference_wrapper<BadgeRoom>, std::greater<>>{};

    auto rows_left = row_budget;
    // The stream ordering of the last row visited. Every row above it has been visited; rows equal
    // to it may not all have been (stream_ordering is not unique).
    auto lowest_visited = std::numeric_limits<std::uint64_t>::max();
    for (auto const& row : store.events.in_stream_order() | std::views::reverse)
    {
        while (!pinned.empty() && pinned.begin()->first > row.stream_ordering)
        {
            settle(pinned.begin()->second.get());
            pinned.erase(pinned.begin());
        }
        if (unsettled == 0U)
        {
            break;
        }
        if (rows_left == 0U)
        {
            result.capped = true;
            break;
        }
        --rows_left;
        lowest_visited = row.stream_ordering;

        auto const found = rooms.find(row.room_id);
        if (found == rooms.end() || found->second.settled)
        {
            continue;
        }
        auto& room = found->second;
        auto const unthreaded = room.markers.unthreaded;

        // current_join_start's transitions. Met newest first: a join->join change (a profile
        // change) leaves the join start undecided; a change from any other membership pins it.
        if (auto transition = member_transition(row, row.room_id, user_id); transition.has_value())
        {
            room.transitions.push_back(*transition);
            if (!transition->second && !room.met_non_join)
            {
                room.met_non_join = true;
                pinned.emplace(transition->first, room);
            }
            else if (transition->second && !room.met_non_join && transition->first <= unthreaded)
            {
                // Every transition above here is a join, so the join start is at or below this
                // one, which the unthreaded marker covers: nothing below can count.
                settle(room);
                continue;
            }
        }

        if (row.sender_user_id == user_id)
        {
            // read_markers_for: a non-state event the user sent reads its own thread up to itself.
            // Walking newest first, every such event above a candidate is met before it.
            if (row.stream_ordering <= unthreaded)
            {
                continue;
            }
            if (auto thread_id = own_event_thread(store, row); thread_id.has_value())
            {
                auto& position = room.markers.threads[*thread_id];
                position = std::max(position, row.stream_ordering);
            }
            continue;
        }

        // sync::count_unread_by_thread's filters; the join start and thread coverage are applied
        // once the walk has met the events that decide them.
        if (row.status != "accepted" || row.stream_ordering <= unthreaded || !classifier.visible(row))
        {
            continue;
        }
        auto const parsed = canonicaljson::parse_lossless(row.json);
        auto const* object = std::get_if<canonicaljson::Object>(&parsed.value.storage());
        if (parsed.error != canonicaljson::ParseError::none || object == nullptr ||
            !classifier.classify(row.room_id, parsed.value).notify)
        {
            continue;
        }
        room.candidates.push_back({row.stream_ordering, sync::event_thread_id(store, *object)});
    }
    result.rows_visited = row_budget - rows_left;
    result.table_walks += classifier.table_walks();

    auto total = std::uint64_t{0U};
    for (auto& [room_id, room] : rooms)
    {
        // An unsettled room in a capped walk knows only the rows above `lowest_visited`: its own
        // events and membership changes there are all known, so counting only candidates above it
        // never counts an event /sync would not. Otherwise the room is exact.
        auto const partial = result.capped && !room.settled;
        auto transitions = std::move(room.transitions);
        if (partial)
        {
            std::erase_if(transitions, [lowest_visited](std::pair<std::uint64_t, bool> const& transition) {
                return transition.first <= lowest_visited;
            });
        }
        auto const transitions_known = !transitions.empty();
        auto start = join_start_from(std::move(transitions));
        // A capped walk that met none of the room's membership changes falls back to the membership
        // row: every path that stores an accepted m.room.member event for the user rewrites its
        // ordering with the event's or a later one, so it is never before the join start and can
        // only under-count. Only joins met, the earliest of them is at or after the join start too.
        if (partial && !transitions_known && room.membership_row_ordering != 0U)
        {
            start = room.membership_row_ordering;
        }
        if (!start.has_value())
        {
            continue;
        }
        for (auto const& candidate : room.candidates)
        {
            // Strictly above: a row at `lowest_visited` may share its ordering with an unvisited row.
            if ((partial && candidate.stream_ordering <= lowest_visited) || candidate.stream_ordering <= *start ||
                room.markers.covers(candidate.stream_ordering, candidate.thread_id))
            {
                continue;
            }
            ++total;
        }
    }
    result.unread = static_cast<std::uint32_t>(std::min<std::uint64_t>(total, push_badge_unread_cap));
    return result;
}

auto push_badge_unread_count(HomeserverRuntime const& runtime, std::string_view user_id,
                             push::PushRuleset const& ruleset) -> std::uint32_t
{
    return count_push_badge(runtime, user_id, ruleset).unread;
}

} // namespace merovingian::homeserver
