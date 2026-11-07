// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/http/RateLimitPolicy.hpp"
#include "merovingian/observability/AdminOperation.hpp"

#include <string>

namespace merovingian::observability
{

struct AdminRoute final
{
    std::string method{};
    std::string path_template{};
    AdminOperation operation{AdminOperation::health};
    bool requires_admin{true};
    http::RateLimitPolicy rate_limit{};
};

} // namespace merovingian::observability
