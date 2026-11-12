// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/sync/SlidingSyncRoomList.hpp"

#include "merovingian/homeserver/PushRuleUnreadClassifier.hpp"
#include "merovingian/sync/RoomListResult.hpp"
#include "merovingian/sync/SlidingSyncRequestLookups.hpp"
#include "merovingian/sync/SlidingSyncRoomBuilder.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace merovingian::sync
{
namespace
{

    // ── Filter helpers ─────────────────────────────────────────────────────

    // Whether a room passes the list's filters. Every answer comes from the request's lookups, built once per request,
    // never from a scan of a server-wide table per room (ADR-0665).
    [[nodiscard]] auto passes_filters(SlidingSyncRequestLookups& lookups, std::string_view room_id,
                                      SlidingSyncFilters const& f) -> bool
    {
        if (f.is_encrypted.has_value() && lookups.is_encrypted(room_id) != *f.is_encrypted)
        {
            return false;
        }
        if (f.is_invite.has_value() && lookups.is_invited(room_id) != *f.is_invite)
        {
            return false;
        }
        if (f.is_dm.has_value() && lookups.is_dm(room_id) != *f.is_dm)
        {
            return false;
        }
        if (f.is_favourite.has_value() && lookups.is_favourite(room_id) != *f.is_favourite)
        {
            return false;
        }
        if (!f.room_types.empty() || !f.not_room_types.empty())
        {
            auto const& type = lookups.room_type(room_id);
            if (!f.room_types.empty() && !std::ranges::any_of(f.room_types, [&](std::string const& t) {
                    return t == type;
                }))
            {
                return false;
            }
            if (!f.not_room_types.empty() && std::ranges::any_of(f.not_room_types, [&](std::string const& t) {
                    return t == type;
                }))
            {
                return false;
            }
        }
        return true;
    }

    // ── Sort key helpers ───────────────────────────────────────────────────

    // Every sort key is computed once per room before the sort, never inside
    // the comparator: the comparator runs O(N log N) times while the caller
    // holds the runtime lock (ADR-0172). Recency and name keys come from the request's lookups, per room
    // through the indexes, never from a pass over a whole table (ADR-0666).

    // The room's unread notifications, relative to the user's read receipts
    // (#417) and counted by the user's push rules (R15). Without the receipt
    // baseline this sort key degenerates to "total message count" and every
    // room sorts identically regardless of read state. The same count as the
    // room's notification_count.
    [[nodiscard]] auto notification_key(SlidingSyncRequestLookups& lookups, database::PersistentStore const& store,
                                        std::string_view room_id, std::string_view user, UnreadEventClassifier& unread)
        -> std::uint64_t
    {
        return count_notifications(store, room_id, user, lookups.read_markers(room_id), unread);
    }

    // ── Ops generation ─────────────────────────────────────────────────────

    // Build the windowed room IDs for the given ranges from the full sorted list.
    [[nodiscard]] auto window_rooms(std::vector<std::string> const& sorted, std::vector<SlidingSyncRange> const& ranges)
        -> std::vector<std::string>
    {
        auto out = std::vector<std::string>{};
        for (auto const& range : ranges)
        {
            auto const start = static_cast<std::size_t>(range.start);
            auto const end = static_cast<std::size_t>(range.end);
            for (auto i = start; i <= end && i < sorted.size(); ++i)
            {
                out.push_back(sorted[i]);
            }
        }
        return out;
    }

    // Emit SYNC ops covering all requested ranges.
    [[nodiscard]] auto make_sync_ops(std::vector<std::string> const& sorted,
                                     std::vector<SlidingSyncRange> const& ranges) -> std::vector<SlidingSyncOp>
    {
        auto ops = std::vector<SlidingSyncOp>{};
        for (auto const& range : ranges)
        {
            auto op = SlidingSyncOp{};
            op.op = "SYNC";
            op.range = range;
            auto const start = static_cast<std::size_t>(range.start);
            auto const end = static_cast<std::size_t>(range.end);
            for (auto i = start; i <= end && i < sorted.size(); ++i)
            {
                op.room_ids.push_back(sorted[i]);
            }
            ops.push_back(std::move(op));
        }
        return ops;
    }

} // namespace

auto compute_room_list(homeserver::HomeserverRuntime const& rt, std::string_view user, SlidingSyncList const& list,
                       std::vector<std::string> const& prev_window, database::PersistentStore const& store)
    -> RoomListResult
{
    auto unread = homeserver::PushRuleUnreadClassifier{
        store, user, static_cast<std::size_t>(rt.config.server().client_api.max_push_rules_per_user)};
    return compute_room_list(rt, user, list, prev_window, store, unread);
}

auto compute_room_list(homeserver::HomeserverRuntime const& rt, std::string_view user, SlidingSyncList const& list,
                       std::vector<std::string> const& prev_window, database::PersistentStore const& store,
                       UnreadEventClassifier& unread) -> RoomListResult
{
    auto lookups = SlidingSyncRequestLookups{store, user, &rt.database.persistent_store.receipts};
    return compute_room_list(user, list, prev_window, store, unread, lookups);
}

auto compute_room_list(std::string_view user, SlidingSyncList const& list, std::vector<std::string> const& prev_window,
                       database::PersistentStore const& store, UnreadEventClassifier& unread,
                       SlidingSyncRequestLookups& lookups) -> RoomListResult
{

    // Step 1 — the rooms where the user is joined, from the user's own membership rows (ADR-0609), read once per
    // request. The persistent store is the source of truth rather than the runtime cache, so sliding sync reports the
    // same rooms as the database of record even when the in-memory cache is stale or was never hydrated.
    auto joined_room_ids = lookups.joined_rooms();

    // Step 2 — apply filters, each answered from the request's lookups (ADR-0665).
    if (list.filters.has_value())
    {
        auto const& f = *list.filters;
        std::erase_if(joined_room_ids, [&](std::string const& room_id) {
            return !passes_filters(lookups, room_id, f);
        });
    }

    auto const total_count = static_cast<std::uint64_t>(joined_room_ids.size());

    // Compute each requested sort key once per room. The sort comparator may
    // run O(N log N) times while the caller holds the runtime lock, so it only
    // looks keys up (ADR-0172).
    auto const sorts_by = [&list](std::string_view key) {
        return std::ranges::find(list.sort, key) != list.sort.end();
    };
    auto notification_keys = std::unordered_map<std::string, std::uint64_t>{};
    if (sorts_by("by_notification_count"))
    {
        notification_keys.reserve(joined_room_ids.size());
        for (auto const& room_id : joined_room_ids)
        {
            notification_keys.emplace(room_id, notification_key(lookups, store, room_id, user, unread));
        }
    }
    auto recency = std::unordered_map<std::string, std::uint64_t>{};
    if (sorts_by("by_recency"))
    {
        recency.reserve(joined_room_ids.size());
        for (auto const& room_id : joined_room_ids)
        {
            recency.emplace(room_id, lookups.recency(room_id, list.bump_event_types));
        }
    }
    auto names = std::unordered_map<std::string, std::string>{};
    if (sorts_by("by_name"))
    {
        names.reserve(joined_room_ids.size());
        for (auto const& room_id : joined_room_ids)
        {
            names.emplace(room_id, lookups.room_name(room_id));
        }
    }

    // Step 3 — sort.
    // Sort keys are applied left-to-right; ties fall through to the next key.
    std::stable_sort(joined_room_ids.begin(), joined_room_ids.end(), [&](std::string const& a, std::string const& b) {
        for (auto const& key : list.sort)
        {
            if (key == "by_notification_count")
            {
                auto const na = notification_keys.at(a);
                auto const nb = notification_keys.at(b);
                if (na != nb)
                {
                    return na > nb; // descending
                }
            }
            else if (key == "by_recency")
            {
                auto const ra = recency.at(a);
                auto const rb = recency.at(b);
                if (ra != rb)
                {
                    return ra > rb; // most-recent first
                }
            }
            else if (key == "by_name")
            {
                auto const& na = names.at(a);
                auto const& nb = names.at(b);
                // Unnamed rooms sort last.
                if (na.empty() != nb.empty())
                {
                    return !na.empty();
                }
                if (na != nb)
                {
                    return na < nb;
                }
            }
        }
        // Final tie-break: room_id lexicographic (stable).
        return a < b;
    });

    // Step 4 — window and generate ops.
    auto const current_window = window_rooms(joined_room_ids, list.ranges);
    auto ops = std::vector<SlidingSyncOp>{};

    if (prev_window.empty())
    {
        // Initial request for this list: emit SYNC for all ranges.
        ops = make_sync_ops(joined_room_ids, list.ranges);
    }
    else
    {
        // Incremental: emit SYNC only for ranges whose contents changed.
        auto prev_offset = std::size_t{0U};
        for (auto const& range : list.ranges)
        {
            auto const start = static_cast<std::size_t>(range.start);
            auto const end = static_cast<std::size_t>(range.end);
            auto const len = end >= start ? (end - start + 1U) : 0U;

            // Slice of current window for this range.
            auto current_slice = std::vector<std::string>{};
            for (auto i = start; i <= end && i < joined_room_ids.size(); ++i)
            {
                current_slice.push_back(joined_room_ids[i]);
            }

            // Corresponding slice of the previous window.
            auto prev_slice = std::vector<std::string>{};
            for (auto i = prev_offset; i < prev_offset + len && i < prev_window.size(); ++i)
            {
                prev_slice.push_back(prev_window[i]);
            }
            prev_offset += len;

            if (current_slice != prev_slice)
            {
                auto op = SlidingSyncOp{};
                op.op = "SYNC";
                op.range = range;
                op.room_ids = current_slice;
                ops.push_back(std::move(op));
            }
        }
    }

    return RoomListResult{total_count, current_window, std::move(ops)};
}

} // namespace merovingian::sync
