// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/sync/RequiredStateConfig.hpp"

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace merovingian::sync
{

// MSC4186 §room_subscriptions[roomId] — subscribe to a specific room regardless of list membership.
struct SlidingSyncRoomSubscription final
{
    // The MSC3575 form, kept for clients that send it ("$LAZY" and "$ME" are sentinels there).
    std::vector<std::pair<std::string, std::string>> required_state{};
    // The MSC4186 form: one entry for a parsed subscription, and one per combined config after
    // `combine_room_configs` (ADR-0865).
    std::vector<RequiredStateConfig> required_state_configs{};
    std::uint64_t timeline_limit{20U};
    bool include_heroes{false};
};

} // namespace merovingian::sync
