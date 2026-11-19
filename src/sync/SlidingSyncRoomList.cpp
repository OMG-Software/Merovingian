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
#include <iterator>
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
        // MSC4186 `tags` / `not_tags`: any one of `tags`, and none of `not_tags`, which "takes priority over `tags`".
        if (!f.tags.empty() || !f.not_tags.empty())
        {
            auto const& tags = lookups.room_tags(room_id);
            auto const tagged = [&](std::string const& t) {
                return tags.contains(t);
            };
            if (!f.tags.empty() && !std::ranges::any_of(f.tags, tagged))
            {
                return false;
            }
            if (std::ranges::any_of(f.not_tags, tagged))
            {
                return false;
            }
        }
        // MSC4186 `spaces`: a room "can be part of any one of the listed spaces (OR'd)", as a direct child.
        if (!f.spaces.empty() && !std::ranges::any_of(f.spaces, [&](std::string const& space) {
                return lookups.space_children(space).contains(std::string{room_id});
            }))
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

auto room_passes_list_filters(SlidingSyncRequestLookups& lookups, std::string_view room_id,
                              SlidingSyncFilters const& filters) -> bool
{
    return passes_filters(lookups, room_id, filters);
}

auto compute_room_list(homeserver::HomeserverRuntime const& rt, std::string_view user, SlidingSyncList const& list,
                       std::vector<std::string> const& prev_window, database::PersistentStore const& store)
    -> RoomListResult
{
    auto unread = homeserver::PushRuleUnreadClassifier{
        store, user, static_cast<std::size_t>(rt.config.server().client_api.max_push_rules_per_user)};
    return compute_room_list(rt, user, list, prev_window, store, unread);
}

auto compute_room_list(homeserver::HomeserverRuntime const& /*rt*/, std::string_view user, SlidingSyncList const& list,
                       std::vector<std::string> const& prev_window, database::PersistentStore const& store,
                       UnreadEventClassifier& unread) -> RoomListResult
{
    auto lookups = SlidingSyncRequestLookups{store, user};
    return compute_room_list(user, list, prev_window, store, unread, lookups);
}

auto compute_room_list(std::string_view user, SlidingSyncList const& list, std::vector<std::string> const& prev_window,
                       database::PersistentStore const& store, UnreadEventClassifier& unread,
                       SlidingSyncRequestLookups& lookups) -> RoomListResult
{

    // Step 1 — the rooms where the user is joined, from the user's own membership rows (ADR-0609), read once per
    // request, and the rooms they are invited to (MSC4186: a list holds both unless `is_invite` says otherwise;
    // ADR-0864). The persistent store is the source of truth rather than the runtime cache, so sliding sync reports the
    // same rooms as the database of record even when the in-memory cache is stale or was never hydrated. Every key and
    // filter below answers an invited room from its invite, never from the room's events or state.
    // MSC4186 "Lists" adds the rooms the user knocked on, and those `include_departed_rooms` kept of the ones they
    // left or were kicked or banned from (ADR-0867), each answered from its membership as an invite is.
    auto room_ids = lookups.joined_rooms();
    std::ranges::move(lookups.invited_rooms(), std::back_inserter(room_ids));
    std::ranges::move(lookups.knocked_rooms(), std::back_inserter(room_ids));
    std::ranges::move(lookups.departed_rooms(), std::back_inserter(room_ids));

    // Step 2 — apply filters, each answered from the request's lookups (ADR-0665).
    if (list.filters.has_value())
    {
        auto const& f = *list.filters;
        std::erase_if(room_ids, [&](std::string const& room_id) {
            return !passes_filters(lookups, room_id, f);
        });
    }

    auto const total_count = static_cast<std::uint64_t>(room_ids.size());

    // MSC4186 "SyncListConfig": with no `range` "the room list is not limited by range", so the window is the whole
    // filtered list. MSC4186 "Activity ordering": without MSC3575's `sort`, rooms are ordered by last activity.
    auto list_with_window = list;
    if (list.whole_list && !room_ids.empty())
    {
        list_with_window.ranges = {
            SlidingSyncRange{0U, total_count - 1U}
        };
    }
    if (list_with_window.sort.empty())
    {
        list_with_window.sort = {"by_recency"};
    }
    auto const& windowed = list_with_window;

    // Compute each requested sort key once per room. The sort comparator may
    // run O(N log N) times while the caller holds the runtime lock, so it only
    // looks keys up (ADR-0172).
    auto const sorts_by = [&windowed](std::string_view key) {
        return std::ranges::find(windowed.sort, key) != windowed.sort.end();
    };
    auto notification_keys = std::unordered_map<std::string, std::uint64_t>{};
    if (sorts_by("by_notification_count"))
    {
        notification_keys.reserve(room_ids.size());
        for (auto const& room_id : room_ids)
        {
            // A room the user is not joined to has no unread count they may be told (ADR-0864, ADR-0867).
            notification_keys.emplace(room_id, lookups.is_unjoined(room_id)
                                                   ? std::uint64_t{0U}
                                                   : notification_key(lookups, store, room_id, user, unread));
        }
    }
    auto recency = std::unordered_map<std::string, std::uint64_t>{};
    if (sorts_by("by_recency"))
    {
        recency.reserve(room_ids.size());
        for (auto const& room_id : room_ids)
        {
            recency.emplace(room_id, lookups.recency(room_id, list.bump_event_types));
        }
    }
    auto names = std::unordered_map<std::string, std::string>{};
    if (sorts_by("by_name"))
    {
        names.reserve(room_ids.size());
        for (auto const& room_id : room_ids)
        {
            names.emplace(room_id, lookups.room_name(room_id));
        }
    }

    // Step 3 — sort.
    // Sort keys are applied left-to-right; ties fall through to the next key.
    std::stable_sort(room_ids.begin(), room_ids.end(), [&](std::string const& a, std::string const& b) {
        for (auto const& key : windowed.sort)
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
    auto const current_window = window_rooms(room_ids, windowed.ranges);
    auto ops = std::vector<SlidingSyncOp>{};

    if (prev_window.empty())
    {
        // Initial request for this list: emit SYNC for all ranges.
        ops = make_sync_ops(room_ids, windowed.ranges);
    }
    else
    {
        // Incremental: emit SYNC only for ranges whose contents changed.
        auto prev_offset = std::size_t{0U};
        for (auto const& range : windowed.ranges)
        {
            auto const start = static_cast<std::size_t>(range.start);
            auto const end = static_cast<std::size_t>(range.end);
            auto const len = end >= start ? (end - start + 1U) : 0U;

            // Slice of current window for this range.
            auto current_slice = std::vector<std::string>{};
            for (auto i = start; i <= end && i < room_ids.size(); ++i)
            {
                current_slice.push_back(room_ids[i]);
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
