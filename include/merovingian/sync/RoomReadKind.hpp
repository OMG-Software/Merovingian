// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::sync
{

// How much of a room's state a user may read.
enum class RoomReadKind
{
    // Never joined (invite, knock, a declined invite, no membership at all), or forgotten.
    none,
    // Joined now: the room's current state.
    current,
    // Was joined and has since left, been kicked or banned: the state as of the event that
    // ended the join.
    as_of,
};

} // namespace merovingian::sync
