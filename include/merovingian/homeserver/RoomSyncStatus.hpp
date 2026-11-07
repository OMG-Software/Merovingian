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
};

} // namespace merovingian::homeserver
