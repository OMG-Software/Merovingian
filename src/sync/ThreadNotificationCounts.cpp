// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/sync/ThreadNotificationCounts.hpp"

#include "merovingian/sync/NotificationCounts.hpp"

namespace merovingian::sync
{

auto ThreadNotificationCounts::total() const noexcept -> NotificationCounts
{
    auto sum = NotificationCounts{};
    for (auto const& [thread_id, counts] : threads)
    {
        sum.notification_count += counts.notification_count;
        sum.highlight_count += counts.highlight_count;
    }
    return sum;
}

} // namespace merovingian::sync
