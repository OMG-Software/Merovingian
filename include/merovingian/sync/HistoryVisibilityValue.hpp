// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::sync
{

// The four values of `m.room.history_visibility`'s `history_visibility`.
enum class HistoryVisibilityValue
{
    world_readable,
    shared,
    invited,
    joined,
};

} // namespace merovingian::sync
