// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/observability/MetricLabel.hpp"
#include "merovingian/observability/MetricType.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace merovingian::observability
{

struct MetricSample final
{
    std::string name{};
    std::int64_t value{0};
    bool secret_safe{true};
    MetricType type{MetricType::gauge};
    std::string help{};
    std::vector<MetricLabel> labels{};
};

} // namespace merovingian::observability
