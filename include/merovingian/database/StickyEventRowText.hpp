// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/PersistentStickyEvent.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace merovingian::database
{

// The number of columns of a `sticky_events` row, in the order the loaders select them: `event_id`, `room_id`,
// `sender`, `received_at_ms`, `expires_at_ms`.
inline constexpr auto sticky_event_row_columns = std::size_t{5U};

// The number of columns of a `delayed_event_sticky_durations` row: `delay_id`, `sticky_duration_ms`.
inline constexpr auto delayed_event_sticky_duration_row_columns = std::size_t{2U};

// The strict reading of one stored `sticky_events` row, shared by both backends' loaders. Nullopt (the row is skipped,
// never repaired or guessed) unless there are at least `sticky_event_row_columns` columns, each text column is
// storable (`sticky_event_is_storable`: non-empty, at most 255 bytes, no NUL) and both times are one or more ASCII
// digits that fit 63 bits. Whether the row has expired is not judged here.
[[nodiscard]] auto parse_sticky_event_row(std::span<std::string const> columns) -> std::optional<PersistentStickyEvent>;

// The strict reading of a sticky duration in milliseconds: one or more ASCII digits that fit 63 bits and are at least
// 1. Nullopt for anything else (empty, a sign, a space, a letter, zero, an overflow).
[[nodiscard]] auto parse_sticky_duration_ms(std::string_view text) noexcept -> std::optional<std::int64_t>;

} // namespace merovingian::database
