// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::push
{

struct PushGatewayCounts final
{
    std::uint32_t unread{0U};
    std::uint32_t missed_calls{0U};
};

} // namespace merovingian::push
