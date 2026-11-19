// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::config
{

// Sticky events (MSC4354; ADR-0854): the operator's switch and the per-sender cap. Both keys are snapshotted at
// start-up, so a change needs a restart. validate() refuses a value outside the range named on each member.
struct StickyEventsConfig final
{
    // Off: a sticky send is refused (403) and the sticky sections are not served. Stored events are unchanged.
    bool enabled{true};
    // Unexpired sticky events one sender may hold, across all rooms; the oldest expires first. 1..1000.
    std::uint32_t max_per_sender{60U};
};

} // namespace merovingian::config
