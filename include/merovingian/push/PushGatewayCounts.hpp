// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <optional>

namespace merovingian::push
{

struct PushGatewayCounts final
{
    // Absent when no count is known (the badge budget was spent): the notification then omits `unread` and
    // the client keeps its last badge. Present and zero is omitted on the wire too ("Counts whose value is
    // zero should be omitted").
    std::optional<std::uint32_t> unread{};
    std::uint32_t missed_calls{0U};
};

} // namespace merovingian::push
