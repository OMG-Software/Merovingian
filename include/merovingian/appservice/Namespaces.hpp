// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/appservice/Namespace.hpp"

#include <vector>

namespace merovingian::appservice
{

struct Namespaces final
{
    std::vector<Namespace> users{};
    std::vector<Namespace> aliases{};
    std::vector<Namespace> rooms{};
};

} // namespace merovingian::appservice
