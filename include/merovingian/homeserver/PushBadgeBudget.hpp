// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::homeserver
{

// The event rows every badge one event causes may visit between them (ADR-0608). Push delivery
// computes a badge per recipient with an http pusher, under runtime.mutex, so a per-recipient
// budget made one event cost recipients times that budget.
inline constexpr auto push_badge_event_row_budget = std::uint64_t{10000U};

// The badges one event computes at all. A recipient past it, or past the rows above, is given the
// lower bound push_badge_lower_bound without any walk (ADR-0608).
inline constexpr auto push_badge_calls_per_event = std::uint32_t{16U};

// What a recipient is told when the event's budget is spent: the notifying event itself, which is
// unread by definition. A lower bound, never more than the exact count.
inline constexpr auto push_badge_lower_bound = std::uint32_t{1U};

// What the badges of one event may spend, shared by all its recipients. Build one per event, under
// runtime.mutex, and pass it to every push_badge_unread_count for that event.
struct PushBadgeBudget final
{
    std::uint64_t rows_left{push_badge_event_row_budget};
    std::uint32_t calls_left{push_badge_calls_per_event};
};

} // namespace merovingian::homeserver
