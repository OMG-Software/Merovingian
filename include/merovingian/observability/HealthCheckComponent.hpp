// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/observability/HealthStatus.hpp"

#include <string>

namespace merovingian::observability
{

struct HealthCheckComponent final
{
    std::string name{};
    HealthStatus status{HealthStatus::ok};
    std::string summary{};
};

} // namespace merovingian::observability
