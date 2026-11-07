// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/federation/FederationRoute.hpp"

#include <string>

namespace merovingian::federation
{

struct FederationRouteMatch final
{
    bool matched{false};
    FederationRoute route{};
    std::string reason{};
};

} // namespace merovingian::federation
