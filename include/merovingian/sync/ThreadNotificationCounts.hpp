// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/sync/NotificationCounts.hpp"

#include <functional>
#include <map>
#include <string>

namespace merovingian::sync
{

// A room's unread counts split by thread: `main` for the main timeline, a
// thread root's event ID for each thread. A thread with nothing unread has no
// entry.
struct ThreadNotificationCounts final
{
    std::map<std::string, NotificationCounts, std::less<>> threads{};

    [[nodiscard]] auto total() const noexcept -> NotificationCounts;
};

} // namespace merovingian::sync
