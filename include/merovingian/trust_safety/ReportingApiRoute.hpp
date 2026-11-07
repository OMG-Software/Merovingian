// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/http/RateLimitPolicy.hpp"

#include <string>

namespace merovingian::trust_safety
{

struct ReportingApiRoute final
{
    std::string method{};
    std::string path_template{};
    bool requires_access_token{true};
    bool requires_admin{false};
    http::RateLimitPolicy rate_limit{};
};

} // namespace merovingian::trust_safety
