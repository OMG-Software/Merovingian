// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/observability/HealthCheckComponent.hpp"
#include "merovingian/observability/HealthStatus.hpp"

#include <vector>

namespace merovingian::observability
{

struct HealthCheckSnapshot final
{
    HealthStatus status{HealthStatus::ok};
    std::vector<HealthCheckComponent> components{};
};

} // namespace merovingian::observability
