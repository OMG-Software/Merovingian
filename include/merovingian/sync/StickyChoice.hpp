// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>
#include <vector>

namespace merovingian::sync
{

// What `select_sticky_for_sync` chose for one room.
struct StickyChoice final
{
    // Event IDs, oldest first.
    std::vector<std::string> event_ids{};
    // Eligible events remain that the limit held back.
    bool more{false};
};

} // namespace merovingian::sync
