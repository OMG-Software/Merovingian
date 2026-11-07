// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>
#include <vector>

namespace merovingian::federation
{

struct ResolvedAddressSet final
{
    bool ok{false};
    std::vector<std::string> addresses{};
    std::string reason{};
};

} // namespace merovingian::federation
