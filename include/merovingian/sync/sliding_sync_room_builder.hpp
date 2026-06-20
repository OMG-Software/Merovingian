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
// `since_event_ordering` — stream_ordering floor for incremental timeline.
//                0 on initial sync (return full timeline up to limit).
// `is_initial` — true when room_id has not appeared in any prior response for
//                this connection (caller checks rooms_seen).
[[nodiscard]] auto build_room_response(
    homeserver::HomeserverRuntime const&    rt,
    std::string_view                        room_id,
    std::string_view                        user,
    SlidingSyncRoomSubscription const&      sub,
    std::uint64_t                           since_event_ordering,
    bool                                    is_initial,
    database::PersistentStore const&        store) -> SlidingSyncRoomResponse;

} // namespace merovingian::sync
