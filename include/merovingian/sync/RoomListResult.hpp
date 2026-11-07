// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/sync/SlidingSyncOp.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace merovingian::sync
{

// Result of computing one named room list for an MSC4186 sliding sync response.
struct RoomListResult final
{
    // Total number of rooms matching the list's filters (for list.count).
    std::uint64_t count{0U};
    // Ordered room IDs covering the union of all requested ranges.
    std::vector<std::string> windowed_room_ids{};
    // Ops to include in the list response.
    std::vector<SlidingSyncOp> ops{};
};

} // namespace merovingian::sync
