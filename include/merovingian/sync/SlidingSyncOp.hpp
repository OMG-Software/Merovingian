// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/sync/SlidingSyncRange.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace merovingian::sync
{

// MSC4186 §ops — one operation describing how the client's room list changed.
struct SlidingSyncOp final
{
    // "SYNC" | "INVALIDATE" | "INSERT" | "DELETE" | "UPDATE"
    std::string op{};
    // Present for SYNC and INVALIDATE.
    std::optional<SlidingSyncRange> range{};
    // Present for SYNC — the ordered room IDs covering the range.
    std::vector<std::string> room_ids{};
    // Present for INSERT, DELETE, UPDATE — the affected list position.
    std::optional<std::uint64_t> index{};
    // Present for INSERT and UPDATE — the room at that position.
    std::optional<std::string> room_id{};
};

} // namespace merovingian::sync
