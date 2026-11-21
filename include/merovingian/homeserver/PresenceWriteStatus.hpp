// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::homeserver
{

// What became of a presence a user set (`set_presence`).
enum class PresenceWriteStatus : std::uint8_t
{
    // Stored and sent, or accepted and dropped because presence is off.
    stored,
    // Not stored: refused by `AccountPresenceTracker` (ADR-0876). The account's presence changed less than
    // `AccountPresenceTracker::change_window_ms` ago, or, when `PresenceWrite::tracker_full` is set, the table had no
    // room for the account, whose presence need not have changed at all.
    limited,
    // The store refused the row.
    failed,
};

} // namespace merovingian::homeserver
