// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::ipc
{

// A federation worker's request for one page of a room snapshot (ADR-0733). `generation` is the room_sync
// generation the worker is reloading for, or 0 for the start-up fill. Main serves it only under a permit it issued
// for this channel.
struct RoomSnapshotPageRequest final
{
    std::string room_id{};
    std::uint64_t generation{0U};
    std::uint64_t page{0U};
};

} // namespace merovingian::ipc
