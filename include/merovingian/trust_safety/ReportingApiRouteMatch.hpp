// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/trust_safety/ReportingApiRoute.hpp"

#include <string>

namespace merovingian::trust_safety
{

struct ReportingApiRouteMatch final
{
    bool matched{false};
    ReportingApiRoute route{};
    std::string reason{};
};

} // namespace merovingian::trust_safety
