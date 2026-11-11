// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/PersistentEvent.hpp"
#include "merovingian/database/PersistentStore.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string_view>
#include <vector>

namespace merovingian::sync
{

// The rows of a room a /sync timeline may pass over without taking one (ADR-0616). A window that reaches its limit
// never comes near it; only a filter or a visibility rule that refuses this many rows in a row does.
inline constexpr std::size_t max_timeline_rows_skipped{1000U};

// The newest end of a room's timeline, as `newest_timeline_window` found it.
struct TimelineWindow final
{
    // Oldest first, at most the cap plus one: more than the cap means older events were left out.
    std::vector<database::PersistentEvent const*> matched{};
    // The walk stopped at `max_timeline_rows_skipped` with older rows unread, so the window may have left events out.
    bool budget_ran_out{false};
    // The stream ordering of the oldest row read, whether or not it was taken.
    std::optional<std::uint64_t> oldest_examined{};
};

// Walks the rows of `room_id` above `after` and at or below `up_to`, newest first, through the event table's room
// index, and stops once it holds `cap` plus one rows `wanted` accepts or has passed over the budget. The work is the
// window, never the room's history. Rejected and soft-failed rows are never taken and never offered to `wanted`.
[[nodiscard]] auto newest_timeline_window(database::PersistentStore const& store, std::string_view room_id,
                                          std::optional<std::uint64_t> after, std::uint64_t up_to, std::size_t cap,
                                          std::function<bool(database::PersistentEvent const&)> const& wanted)
    -> TimelineWindow;

} // namespace merovingian::sync
