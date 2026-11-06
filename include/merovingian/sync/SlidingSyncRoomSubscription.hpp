// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace merovingian::sync
{

// MSC4186 §room_subscriptions[roomId] — subscribe to a specific room regardless of list membership.
struct SlidingSyncRoomSubscription final
{
    std::vector<std::pair<std::string, std::string>> required_state{};
    std::uint64_t timeline_limit{20U};
    bool include_heroes{false};
};

} // namespace merovingian::sync
