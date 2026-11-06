// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/observability/HealthCheckSnapshot.hpp"
#include "merovingian/observability/MetricSample.hpp"

#include <string>
#include <vector>

namespace merovingian::observability
{

struct ObservabilitySnapshot final
{
    HealthCheckSnapshot health{};
    std::vector<MetricSample> metrics{};
    std::vector<std::string> hardening_summaries{};
};

} // namespace merovingian::observability
