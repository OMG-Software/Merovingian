// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::config
{

struct TrustSafetySecurityConfig final
{
    bool enabled{false};
    std::string policy_server_url{};
    std::string policy_server_timeout{"5s"};
    bool policy_server_allow_without_result{false};
};

} // namespace merovingian::config
