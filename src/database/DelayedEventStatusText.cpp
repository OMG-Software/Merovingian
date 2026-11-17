// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/database/DelayedEventStatusText.hpp"

namespace merovingian::database
{

auto delayed_event_status_text(DelayedEventStatus status) noexcept -> std::string_view
{
    switch (status)
    {
    case DelayedEventStatus::scheduled:
        return "scheduled";
    case DelayedEventStatus::sent:
        return "sent";
    case DelayedEventStatus::cancelled:
        return "cancelled";
    case DelayedEventStatus::failed:
        return "failed";
    }
    return "scheduled";
}

auto parse_delayed_event_status(std::string_view text) noexcept -> std::optional<DelayedEventStatus>
{
    for (auto const status : {DelayedEventStatus::scheduled, DelayedEventStatus::sent, DelayedEventStatus::cancelled,
                              DelayedEventStatus::failed})
    {
        if (text == delayed_event_status_text(status))
        {
            return status;
        }
    }
    return std::nullopt;
}

} // namespace merovingian::database
