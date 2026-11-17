// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/PersistentDelayedEvent.hpp"

#include <cstddef>
#include <optional>
#include <span>
#include <string>

namespace merovingian::database
{

// The number of columns of a `delayed_events` row, in the order the loaders select them: `delay_id`, `user_id`,
// `device_id`, `room_id`, `event_type`, `is_state`, `state_key`, `content_json`, `txn_id`, `via_appservice`,
// `delay_ms`, `delayed_since_ms`, `status`, `finalised_at_ms`, `event_id`, `error_json`.
inline constexpr auto delayed_event_row_columns = std::size_t{16U};

// The strict reading of one stored `delayed_events` row, shared by both backends' loaders. Nullopt (the row is
// skipped, never repaired or guessed) unless: there are at least `delayed_event_row_columns` columns; `delay_ms`,
// `delayed_since_ms` and `finalised_at_ms` are each one or more ASCII digits that fit 64 bits; the status is one of
// the four; both boolean columns are exactly "true" or "false"; a scheduled row's `delay_ms` is between 1 and
// `max_delayed_event_delay_ms`; and a finalised row's `finalised_at_ms` is not 0. Reading a number as 0 would load a
// scheduled row as due at once, which is early.
[[nodiscard]] auto parse_delayed_event_row(std::span<std::string const> columns)
    -> std::optional<PersistentDelayedEvent>;

} // namespace merovingian::database
