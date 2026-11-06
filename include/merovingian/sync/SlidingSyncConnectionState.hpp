// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/sync/SlidingSyncList.hpp"
#include "merovingian/sync/SlidingSyncPendingResponse.hpp"

#include <chrono>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace merovingian::sync
{

// Per-connection state required to compute incremental ops and the initial flag.
// Key in HomeserverRuntime::sliding_sync_connections:
//   user_id + "/" + device_id + "/" + (conn_id ?? "__default__")
struct SlidingSyncConnectionState final
{
    // Previous window contents per list — used to generate incremental ops.
    // Key: list name, value: ordered room IDs returned in the last response.
    std::map<std::string, std::vector<std::string>> list_prev_windows{};
    // Rooms that have appeared in at least one response for this connection,
    // mapped to the event ordering at which they were last returned.  This lets
    // the server compute per-room deltas and avoid re-sending unchanged rooms
    // when the global pos lags behind a room's last inclusion.
    std::unordered_map<std::string, std::uint64_t> rooms_seen{};
    // Member user_ids already delivered via required_state's "$LAZY" sentinel
    // on this connection, keyed by room_id. required_state's normal
    // change-since-floor check would otherwise suppress an old, unchanged
    // member event the client has genuinely never been sent — this set lets
    // the room builder bypass the floor exactly once per member per
    // connection (see build_room_response's lazy_members_already_sent
    // parameter), then fall back to normal floor-gated delta behaviour.
    std::unordered_map<std::string, std::unordered_set<std::string>> lazy_members_sent{};
    // The effective timeline_limit each room was last built with on this connection. MSC4186
    // "Changes to `timeline_limit`": when a request asks for more than this, the room's latest
    // events are resent (expanded_timeline) rather than only those after its delta floor.
    std::unordered_map<std::string, std::uint64_t> room_timeline_limits{};
    // The config each list in list_prev_windows was computed under. While a list's config is
    // unchanged its window moves only when its rooms change (events, memberships, or receipts
    // under the unread sort), and the request is answered when that change ends the long-poll,
    // or at its timeout; so its previous window says which of its rooms a grown timeline_limit
    // expands. A list that is new or changed is computed before the long-poll decision instead.
    // Both maps hold only the lists of the last acknowledged request: MSC4186 lists are not
    // sticky, so a list left out is gone and the same name sent again is new.
    std::map<std::string, SlidingSyncList> list_configs{};
    // Stream position at the end of the last acknowledged response.
    std::uint64_t last_event_ordering{0U};
    std::uint64_t last_sync_stream_id{0U};
    // A response is not committed until the client acknowledges its position.
    // This preserves the full snapshot for cancelled/retried requests.
    std::optional<SlidingSyncPendingResponse> pending_response{};
    // Wall clock of the last request; connections idle > 1 h are evicted.
    std::chrono::steady_clock::time_point last_used{};
};

} // namespace merovingian::sync
