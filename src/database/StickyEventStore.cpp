// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/database/StickyEventStore.hpp"

#include "merovingian/auth/Identity.hpp"
#include "merovingian/database/BoundValue.hpp"
#include "merovingian/database/DelayedEventStatus.hpp"
#include "merovingian/database/DelayedEventStatusText.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/PreparedStatement.hpp"
#include "merovingian/database/StickyEventTable.hpp"

#include <algorithm>
#include <map>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_set>
#include <utility>
#include <vector>

namespace merovingian::database
{
namespace
{

    // A prepared statement takes at most 128 parameters, so a longer list of IDs is several DELETEs in the one
    // transaction.
    constexpr auto delete_ids_per_statement = std::size_t{128U};

    [[nodiscard]] auto text(std::string_view value) -> BoundValue
    {
        return {std::string{value}, false};
    }

    [[nodiscard]] auto number(std::int64_t value) -> BoundValue
    {
        return text(std::to_string(value));
    }

    [[nodiscard]] auto delete_rows_statement(std::vector<std::string> const& event_ids, std::size_t first,
                                             std::size_t count) -> PreparedStatement
    {
        auto sql = std::string{"DELETE FROM sticky_events WHERE event_id IN ("};
        auto parameters = std::vector<BoundValue>{};
        parameters.reserve(count);
        for (auto index = first; index < first + count; ++index)
        {
            sql += parameters.empty() ? "$" : ", $";
            sql += std::to_string(parameters.size() + 1U);
            parameters.push_back(text(event_ids[index]));
        }
        sql += ")";
        return {"delete_sticky_events", std::move(sql), std::move(parameters)};
    }

    // The event IDs to delete so that, once `row` is recorded, its sender holds at most `max_per_sender` unexpired
    // rows: the oldest of the sender's unexpired rows and `row` itself, by (expiry, event ID).
    [[nodiscard]] auto victims_for(StickyEventTable const& table, PersistentStickyEvent const& row,
                                   std::size_t max_per_sender, std::int64_t now_ms) -> std::vector<std::string>
    {
        auto const held = table.unexpired_count_of_sender(row.sender, now_ms);
        if (held + 1U <= max_per_sender)
        {
            return {};
        }
        auto const excess = held + 1U - max_per_sender;
        // At most `excess` of the victims are existing rows, so the `excess` oldest of them are the candidates.
        auto candidates = std::vector<std::pair<std::int64_t, std::string>>{};
        for (auto const* existing : table.oldest_unexpired_of_sender(row.sender, now_ms, excess))
        {
            candidates.emplace_back(existing->expires_at_ms, existing->event_id);
        }
        candidates.emplace_back(row.expires_at_ms, row.event_id);
        std::ranges::sort(candidates);
        auto doomed = std::vector<std::string>{};
        for (auto index = std::size_t{0U}; index < excess && index < candidates.size(); ++index)
        {
            doomed.push_back(std::move(candidates[index].second));
        }
        return doomed;
    }

    // One server's rows of a room in the fair-share eviction below: its rows by (expiry, event ID), oldest first, and
    // how many of them have been taken.
    struct ServerShare final
    {
        std::vector<std::pair<std::int64_t, std::string_view>> rows{};
        std::size_t taken{0U};
    };

    // The rows `share` still holds: those not yet taken.
    [[nodiscard]] auto held(ServerShare const& share) noexcept -> std::size_t
    {
        return share.rows.size() - share.taken;
    }

    // The server whose row the next room eviction takes (ADR-0857): the one holding the most rows; among those tied,
    // `newcomer` (the new row's server) when it is one of them, else the smallest server name (the map's order).
    [[nodiscard]] auto largest_share(std::map<std::string_view, ServerShare>& shares, std::string_view newcomer)
        -> ServerShare&
    {
        auto* chosen = &shares.begin()->second;
        for (auto& [server, share] : shares)
        {
            if (held(share) > held(*chosen))
            {
                chosen = &share;
            }
        }
        if (auto const own = shares.find(newcomer); own != shares.end() && held(own->second) == held(*chosen))
        {
            chosen = &own->second;
        }
        return *chosen;
    }

    // The event IDs to delete so that, once `row` is recorded and `doomed` deleted, its room holds at most
    // `max_per_room` unexpired rows (ADR-0857). Each eviction takes the oldest row, by (expiry, event ID), of the
    // server holding the most rows in the room, the new row included, so a server that floods a room expires only its
    // own rows and every other server keeps a fair share. The new row may be the one taken. The walk is over the
    // room's unexpired rows, at most `max_per_room` of them once the cap holds.
    [[nodiscard]] auto room_victims_for(StickyEventTable const& table, PersistentStickyEvent const& row,
                                        std::vector<std::string> const& doomed, std::size_t max_per_room,
                                        std::int64_t now_ms) -> std::vector<std::string>
    {
        if (std::ranges::find(doomed, row.event_id) != doomed.end())
        {
            return {};
        }
        auto shares = std::map<std::string_view, ServerShare>{};
        auto total = std::size_t{1U};
        for (auto const* const existing : table.unexpired_of_room(row.room_id, now_ms))
        {
            if (std::ranges::find(doomed, existing->event_id) == doomed.end())
            {
                shares[auth::user_id_server_name(existing->sender)].rows.emplace_back(existing->expires_at_ms,
                                                                                      existing->event_id);
                ++total;
            }
        }
        if (total <= max_per_room)
        {
            return {};
        }
        auto const newcomer = auth::user_id_server_name(row.sender);
        shares[newcomer].rows.emplace_back(row.expires_at_ms, row.event_id);
        for (auto& [server, share] : shares)
        {
            std::ranges::sort(share.rows);
        }
        auto victims = std::vector<std::string>{};
        while (total > max_per_room)
        {
            auto& share = largest_share(shares, newcomer);
            victims.emplace_back(share.rows[share.taken].second);
            ++share.taken;
            --total;
        }
        return victims;
    }

} // namespace

auto record_sticky_event(PersistentStore& store, PersistentStickyEvent row, StickyEventCaps caps, std::int64_t now_ms)
    -> StickyEventRecordOutcome
{
    // An event already expired when it arrives (a negative or past `origin_server_ts` included) is not sticky: nothing
    // to write, and not a failure (ADR-0854).
    if (row.expires_at_ms <= now_ms)
    {
        return StickyEventRecordOutcome{true, {}};
    }
    if (!sticky_event_is_storable(row) || caps.max_per_sender == 0U || caps.max_per_room == 0U)
    {
        return StickyEventRecordOutcome{};
    }
    if (store.sticky_events.contains(row.event_id))
    {
        return StickyEventRecordOutcome{true, {}};
    }
    auto doomed = victims_for(store.sticky_events, row, caps.max_per_sender, now_ms);
    for (auto& event_id : room_victims_for(store.sticky_events, row, doomed, caps.max_per_room, now_ms))
    {
        doomed.push_back(std::move(event_id));
    }
    auto const keeps_row = std::ranges::find(doomed, row.event_id) == doomed.end();
    auto existing_victims = std::vector<std::string>{};
    for (auto const& event_id : doomed)
    {
        if (event_id != row.event_id)
        {
            existing_victims.push_back(event_id);
        }
    }
    auto statements = std::vector<PreparedStatement>{};
    if (keeps_row)
    {
        statements.push_back(PreparedStatement{
            "insert_sticky_event",
            "INSERT INTO sticky_events (event_id, room_id, sender, received_at_ms, expires_at_ms) VALUES ($1, $2, $3, "
            "$4, $5)",
            {text(row.event_id), text(row.room_id), text(row.sender), number(row.received_at_ms),
              number(row.expires_at_ms)}
        });
    }
    for (auto first = std::size_t{0U}; first < existing_victims.size(); first += delete_ids_per_statement)
    {
        statements.push_back(delete_rows_statement(
            existing_victims, first, std::min(delete_ids_per_statement, existing_victims.size() - first)));
    }
    if (statements.empty())
    {
        return StickyEventRecordOutcome{true, {}};
    }
    if (!commit_persistent_transaction(store, statements))
    {
        return StickyEventRecordOutcome{};
    }
    // A sender's oldest row can be in any room: name each other room that lost one, so the caller reports it to the
    // federation worker as changed (ADR-0862). The room cap's victims are all in the row's own room.
    auto outcome = StickyEventRecordOutcome{true, {}};
    for (auto const& event_id : existing_victims)
    {
        if (auto const* const victim = store.sticky_events.find(event_id, now_ms);
            victim != nullptr && victim->room_id != row.room_id &&
            std::ranges::find(outcome.other_rooms, victim->room_id) == outcome.other_rooms.end())
        {
            outcome.other_rooms.push_back(victim->room_id);
        }
        std::ignore = store.sticky_events.erase(event_id);
    }
    if (keeps_row)
    {
        std::ignore = store.sticky_events.insert(std::move(row));
    }
    return outcome;
}

auto delete_sticky_event(PersistentStore& store, std::string_view event_id) -> bool
{
    // Always the DELETE: a row that hydration skipped is in the database and is removed with the rest.
    auto const statement =
        PreparedStatement{"delete_sticky_event", "DELETE FROM sticky_events WHERE event_id = $1", {text(event_id)}};
    if (!commit_persistent_transaction(store, {statement}))
    {
        return false;
    }
    std::ignore = store.sticky_events.erase(event_id);
    return true;
}

auto delete_sticky_events_of_user(PersistentStore& store, std::string_view user_id) -> bool
{
    auto const statement =
        PreparedStatement{"delete_sticky_events_of_user", "DELETE FROM sticky_events WHERE sender = $1", {text(user_id)}};
    if (!commit_persistent_transaction(store, {statement}))
    {
        return false;
    }
    std::ignore = store.sticky_events.erase_sender(user_id);
    return true;
}

auto prune_expired_sticky_events(PersistentStore& store, std::int64_t now_ms) -> bool
{
    // The columns are TEXT, so the comparison is on decimal text: a shorter number is smaller, and numbers of one
    // length compare as text. The cutoff is bound three times because a parameter is used once. A row that is not
    // digits compares arbitrarily, which only matters to a row the loaders would have skipped.
    auto const cutoff = std::to_string(now_ms);
    auto const expired = PreparedStatement{
        "delete_expired_sticky_events",
        "DELETE FROM sticky_events WHERE length(expires_at_ms) < length(CAST($1 AS TEXT)) OR "
        "(length(expires_at_ms) = length(CAST($2 AS TEXT)) AND expires_at_ms <= $3)",
        {text(cutoff), text(cutoff), text(cutoff)}
    };
    auto const orphaned = PreparedStatement{
        "delete_orphaned_delayed_event_sticky_durations",
        "DELETE FROM delayed_event_sticky_durations WHERE delay_id NOT IN (SELECT delay_id FROM delayed_events WHERE "
        "status = $1)",
        {text(delayed_event_status_text(DelayedEventStatus::scheduled))}
    };
    if (!commit_persistent_transaction(store, {expired, orphaned}))
    {
        return false;
    }
    std::ignore = store.sticky_events.erase_expired(now_ms);
    return true;
}

} // namespace merovingian::database
