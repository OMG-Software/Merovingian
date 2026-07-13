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
[[nodiscard]] auto build_room_response(homeserver::HomeserverRuntime const& rt, std::string_view room_id,
                                       std::string_view user, SlidingSyncRoomSubscription const& sub,
                                       std::uint64_t room_since_event_ordering, bool is_initial,
                                       database::PersistentStore const& store,
                                       std::unordered_set<std::string> const& lazy_members_already_sent = {})
    -> SlidingSyncRoomResponse;

} // namespace merovingian::sync
