// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/auth/KeyApiRoute.hpp"

#include <string>

namespace merovingian::auth
{

struct KeyApiRouteMatch final
{
    bool matched{false};
    KeyApiRoute route{};
    std::string reason{};
};

} // namespace merovingian::auth
