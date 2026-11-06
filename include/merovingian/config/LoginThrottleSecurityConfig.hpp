// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::config
{

// AUTH-2: the failed-password-login throttle. A password login is refused once
// the account has `max_failures_per_source` failures from one client source
// inside `window` (that source only), or `max_failures_per_account` failures
// across all sources (everyone). The same per-source number bounds the
// password checks of user-interactive auth, counted separately per device.
struct LoginThrottleSecurityConfig final
{
    std::uint32_t max_failures_per_source{5U};
    std::uint32_t max_failures_per_account{50U};
    std::string window{"15m"};
};

} // namespace merovingian::config
