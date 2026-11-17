// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::config
{

// Delayed events (MSC4140; ADR-0826): the operator's switch and limits. All four keys are snapshotted at start-up, so
// a change needs a restart. validate() refuses a value outside the range named on each member.
struct DelayedEventsConfig final
{
    // Off: no new event can be scheduled. Events already scheduled are still sent and can still be managed.
    bool enabled{true};
    // The longest delay accepted, in milliseconds. 1000..2678400000 (31 days). Element Call needs 3600000 or more.
    std::uint64_t max_delay_ms{86'400'000U};
    // Scheduled events one user may hold. 1..1000.
    std::uint32_t max_scheduled_per_user{100U};
    // Finalised (sent, cancelled or failed) events kept per user. 1..1000.
    std::uint32_t max_finalised_per_user{100U};
};

} // namespace merovingian::config
