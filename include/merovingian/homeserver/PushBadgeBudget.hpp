// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>

namespace merovingian::homeserver
{

// The event rows every badge one event causes may visit between them (ADR-0608). Push delivery
// computes a badge per recipient with an http pusher, under runtime.mutex, so a per-recipient
// budget made one event cost recipients times that budget.
inline constexpr auto push_badge_event_row_budget = std::uint64_t{10000U};

// The badges one event computes at all. A recipient past it, or past the rows above, is given no count
// and no walk: its notification omits `unread` (ADR-0608).
inline constexpr auto push_badge_calls_per_event = std::uint32_t{16U};

// What the badges of one event may spend, shared by all its recipients. Build one per event, under
// runtime.mutex, and pass it to every push_badge_unread_count for that event.
struct PushBadgeBudget final
{
    std::uint64_t rows_left{push_badge_event_row_budget};
    std::uint32_t calls_left{push_badge_calls_per_event};
};

// Where in a recipient list an event starts drawing on its PushBadgeBudget: its stream ordering modulo the
// recipient count, so when the budget is short the same members are not always the ones left without a
// count (ADR-0608). Recipients are visited from this index, wrapping. Zero for an empty list.
[[nodiscard]] constexpr auto push_badge_draw_start(std::uint64_t stream_ordering, std::size_t recipient_count) noexcept
    -> std::size_t
{
    return recipient_count == 0U ? std::size_t{0U} : static_cast<std::size_t>(stream_ordering % recipient_count);
}

} // namespace merovingian::homeserver
