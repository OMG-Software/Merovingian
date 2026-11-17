// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/PersistentLiveKitDelegation.hpp"

#include <cstddef>
#include <optional>
#include <span>
#include <string>

namespace merovingian::database
{

// The number of columns of a `livekit_delegations` row, in the order the loaders select them: `delay_id`, `user_id`,
// `room_id`, `slot_id`, `member_id`, `created_ms`.
inline constexpr auto livekit_delegation_row_columns = std::size_t{6U};

// The strict reading of one stored `livekit_delegations` row, shared by both backends' loaders. Nullopt (the row is
// skipped, never repaired or guessed) unless there are at least `livekit_delegation_row_columns` columns, each text
// column is storable (`livekit_delegation_is_storable`) and `created_ms` is one or more ASCII digits that fit 64 bits.
[[nodiscard]] auto parse_livekit_delegation_row(std::span<std::string const> columns)
    -> std::optional<PersistentLiveKitDelegation>;

} // namespace merovingian::database
