// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/sync/sliding_sync.hpp"

#include <cstdint>
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

// Combine a list's room-config fields with a room_subscription's, per MSC4186
// room-config combination: when a room matches both a list and a
// room_subscription, required_state is the superset (union with exact-duplicate
// dedup and wildcard-aware pruning of subsumed pairs), timeline_limit is the
// maximum of the two, and include_heroes is OR'd.
[[nodiscard]] auto combine_room_configs(SlidingSyncList const& list, SlidingSyncRoomSubscription const& sub)
    -> SlidingSyncRoomSubscription;

// Stream ordering of the event named by the user's most recent read receipt
// (m.read or m.read.private) in the room, or 0 when the user has never sent
// one. notification_count / highlight_count and the by_notification_count
// room-list sort count events strictly after this baseline — "events the user
// has not read", not "events the client has not synced" (#417).
[[nodiscard]] auto read_receipt_ordering(homeserver::HomeserverRuntime const& rt,
                                         database::PersistentStore const& store, std::string_view room_id,
                                         std::string_view user) -> std::uint64_t;

// Number of `m.room.message` / `m.room.encrypted` events in the room strictly
// after `read_ordering`, excluding the user's own events. Used for both
// sliding sync and the legacy /sync `unread_notifications.notification_count`.
[[nodiscard]] auto count_notifications(database::PersistentStore const& store, std::string_view room_id,
                                       std::string_view user, std::uint64_t read_ordering) noexcept -> std::uint64_t;

// Subset of count_notifications() whose content mentions `user` via
// `m.mentions.user_ids` (MSC3952 / Matrix v1.7+). Used for both sliding sync
// and the legacy /sync `unread_notifications.highlight_count`.
[[nodiscard]] auto count_highlights(database::PersistentStore const& store, std::string_view room_id,
                                    std::string_view user, std::uint64_t read_ordering) noexcept -> std::uint64_t;

} // namespace merovingian::sync
