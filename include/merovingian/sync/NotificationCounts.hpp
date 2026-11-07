// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::sync
{

// Unread counts of one thread, or of a whole room.
struct NotificationCounts final
{
    std::uint64_t notification_count{0U};
    std::uint64_t highlight_count{0U};
};

} // namespace merovingian::sync
