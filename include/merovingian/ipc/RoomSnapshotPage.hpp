// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/RoomReloadSnapshot.hpp"

#include <cstdint>
#include <string>

namespace merovingian::ipc
{

// One page of a room snapshot main sends a federation worker (ADR-0733). Main packs the room's rows into pages that
// each fit an IPC frame; `rows` holds this page's share, and only page 0 carries `rows.room`. Built by
// deserialize_room_snapshot_page and joined by RoomSnapshotAssembler.
struct RoomSnapshotPage final
{
    std::string room_id{};
    std::uint64_t generation{0U};
    std::uint64_t page{0U};
    std::uint64_t pages{0U};
    database::RoomReloadSnapshot rows{};
};

} // namespace merovingian::ipc
