// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::observability
{

struct MetricLabel final
{
    std::string key{};
    std::string value{};
    bool secret_safe{true};
};

} // namespace merovingian::observability
