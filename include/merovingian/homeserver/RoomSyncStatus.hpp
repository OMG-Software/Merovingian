// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::homeserver
{

// Observed room-sync state of a federation worker shard.
//
// The worker's PersistentStore is a snapshot taken at startup.  When main
// mutates room state it sends a `room_sync` notification; the worker reloads
// the room and reports back whether the reload succeeded.  Main records that
// outcome here and can use it to refuse to serve stale reads from the worker.
struct RoomSyncStatus final
{
    std::string state{};         // "pending", "ok", or "failed"
    std::uint64_t generation{0}; // monotonic per room_id, assigned by main
    // Whether the worker holds a copy of the room at all. A room main notifies for the first time may have been
    // created after the worker's startup fill, so it is not held until the worker reports a successful reload of it;
    // until then every request for the room goes to main (ADR-0756). A room main never notified is held.
    bool held{true};
};

} // namespace merovingian::homeserver
