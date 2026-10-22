// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/sync/history_visibility.hpp"
#include "merovingian/sync/read_markers.hpp"
#include "merovingian/sync/sliding_sync.hpp"
#include "merovingian/sync/unread_event_classifier.hpp"

#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <string_view>
#include <unordered_set>

namespace merovingian::sync
{

// Build the per-room response for one room that appears in a windowed list or
// a room subscription.
//
// `sub`        — the required_state / timeline_limit / include_heroes requested
//                for this room (from a list or room_subscription entry).
// `room_since_event_ordering` — stream_ordering floor for this specific room.
//                0 on the room's first appearance (return full timeline up to
//                limit).  Callers pass max(request pos, last ordering returned
//                for this room on the connection) so already-sent events are
//                not re-delivered when the global pos lags.
// `is_initial` — true when room_id has not appeared in any prior response for
//                this connection (caller checks rooms_seen).
// `lazy_members_already_sent` — member user_ids already delivered to this
//                connection for this room via required_state's "$LAZY"
//                sentinel (caller's committed SlidingSyncConnectionState::
//                lazy_members_sent[room_id], or empty if never used). Members
//                not in this set that are newly relevant this call (see
//                SlidingSyncRoomResponse::lazy_members_included) bypass the
//                normal since-floor so a genuinely new-to-this-connection
//                member is always delivered at least once.
// `ignored_senders` — the requesting user's resolved m.ignored_user_list
// (see trust_safety::resolve_ignored_users), resolved ONCE by the caller for
// the whole sliding sync request and passed down here per room rather than
// re-resolved per call. Applied to the room's timeline: non-state events
// from an ignored sender are withheld; state events are still delivered per
// spec ("Servers must still send state events sent by ignored users to
// clients").
[[nodiscard]] auto build_room_response(homeserver::HomeserverRuntime const& rt, std::string_view room_id,
                                       std::string_view user, SlidingSyncRoomSubscription const& sub,
                                       std::uint64_t room_since_event_ordering, bool is_initial,
                                       database::PersistentStore const& store,
                                       std::unordered_set<std::string> const& lazy_members_already_sent = {},
                                       std::unordered_set<std::string> const& ignored_senders = {})
    -> SlidingSyncRoomResponse;

// As above, with the request's shared `visibility` filter (CSAZ-3). A sliding sync request
// serves many rooms for one user, so the caller builds ONE HistoryVisibility for the whole
// request and passes it to every room: its indexes over the store are built once, not per room.
// The timeline only ever contains events `visibility` lets the user see. `unread` is the
// request's one classifier of unread events (R15), shared across rooms in the same way. The
// overload above builds a filter and a classifier of its own for a single room.
[[nodiscard]] auto build_room_response(homeserver::HomeserverRuntime const& rt, std::string_view room_id,
                                       std::string_view user, SlidingSyncRoomSubscription const& sub,
                                       std::uint64_t room_since_event_ordering, bool is_initial,
                                       database::PersistentStore const& store,
                                       std::unordered_set<std::string> const& lazy_members_already_sent,
                                       std::unordered_set<std::string> const& ignored_senders,
                                       HistoryVisibility& visibility, UnreadEventClassifier const& unread)
    -> SlidingSyncRoomResponse;

// Combine a list's room-config fields with a room_subscription's, per MSC4186
// room-config combination: when a room matches both a list and a
// room_subscription, required_state is the superset (union with exact-duplicate
// dedup and wildcard-aware pruning of subsumed pairs), timeline_limit is the
// maximum of the two, and include_heroes is OR'd.
[[nodiscard]] auto combine_room_configs(SlidingSyncList const& list, SlidingSyncRoomSubscription const& sub)
    -> SlidingSyncRoomSubscription;

// Where the user has read up to in the room, from their m.read and
// m.read.private receipts (unthreaded and per thread). notification_count /
// highlight_count and the by_notification_count room-list sort count the
// events these markers do not cover — "events the user has not read", not
// "events the client has not synced" (#417).
[[nodiscard]] auto read_receipt_markers(homeserver::HomeserverRuntime const& rt, database::PersistentStore const& store,
                                        std::string_view room_id, std::string_view user) -> ReadMarkers;

// Unread counts of one thread, or of a whole room.
struct NotificationCounts final
{
    std::uint64_t notification_count{0U};
    std::uint64_t highlight_count{0U};
};

// A room's unread counts split by thread: `main` for the main timeline, a
// thread root's event ID for each thread. A thread with nothing unread has no
// entry.
struct ThreadNotificationCounts final
{
    std::map<std::string, NotificationCounts, std::less<>> threads{};

    [[nodiscard]] auto total() const noexcept -> NotificationCounts;
};

// The room's unread counts per thread: the events `markers` do not cover, after
// `unread.counted_after(room_id)` and not sent by `user`, that `unread` classifies as
// notifications, and of those the highlights (R15, ADR-0205). Spec: "Notifications are
// determined by the push rules which apply to an event". `/sync` reports them split by thread
// when the filter sets `unread_thread_notifications`, and summed otherwise.
[[nodiscard]] auto count_unread_by_thread(database::PersistentStore const& store, std::string_view room_id,
                                          std::string_view user, ReadMarkers const& markers,
                                          UnreadEventClassifier const& unread) -> ThreadNotificationCounts;

// count_unread_by_thread()'s notifications, summed over threads. Used for both sliding sync
// and the legacy /sync `unread_notifications.notification_count`.
[[nodiscard]] auto count_notifications(database::PersistentStore const& store, std::string_view room_id,
                                       std::string_view user, ReadMarkers const& markers,
                                       UnreadEventClassifier const& unread) -> std::uint64_t;

// count_unread_by_thread()'s highlights, summed over threads. Used for both sliding sync and
// the legacy /sync `unread_notifications.highlight_count`.
// How much work a bounded unread count may still do (ADR-0207): how many more notifications it
// may count, and how many more unread events it may parse and classify. Shared across the rooms
// one count walks. The push badge uses it; `/sync` counts exactly.
struct UnreadScanBudget final
{
    std::uint64_t notifications_left{0U};
    std::uint64_t examinations_left{0U};

    [[nodiscard]] auto exhausted() const noexcept -> bool
    {
        return notifications_left == 0U || examinations_left == 0U;
    }
};

// count_unread_by_thread(), stopping as soon as `budget` is exhausted. count_unread_by_thread() is
// this with an unlimited budget.
[[nodiscard]] auto count_unread_by_thread_within(database::PersistentStore const& store, std::string_view room_id,
                                                 std::string_view user, ReadMarkers const& markers,
                                                 UnreadEventClassifier const& unread, UnreadScanBudget& budget)
    -> ThreadNotificationCounts;

// count_notifications(), stopping as soon as `budget` is exhausted. Each unread event parsed and
// classified spends one examination and each notification counted spends one notification.
[[nodiscard]] auto count_notifications_within(database::PersistentStore const& store, std::string_view room_id,
                                              std::string_view user, ReadMarkers const& markers,
                                              UnreadEventClassifier const& unread, UnreadScanBudget& budget)
    -> std::uint64_t;

[[nodiscard]] auto count_highlights(database::PersistentStore const& store, std::string_view room_id,
                                    std::string_view user, ReadMarkers const& markers,
                                    UnreadEventClassifier const& unread) -> std::uint64_t;

} // namespace merovingian::sync
