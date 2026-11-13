// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace merovingian::ipc
{

// One page of the room list main sends a federation worker for its start-up fill (ADR-0733): the IDs of the rooms
// the worker may then ask a snapshot of, each once.
struct RoomListPage final
{
    std::uint64_t page{0U};
    std::uint64_t pages{0U};
    std::vector<std::string> room_ids{};
};

} // namespace merovingian::ipc
