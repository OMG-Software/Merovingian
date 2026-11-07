// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/observability/AdminRoute.hpp"

#include <string>

namespace merovingian::observability
{

struct AdminRouteMatch final
{
    bool matched{false};
    AdminRoute route{};
    std::string reason{};
};

} // namespace merovingian::observability
