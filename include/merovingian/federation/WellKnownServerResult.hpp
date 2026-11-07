// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::federation
{

struct WellKnownServerResult final
{
    bool found{false};
    bool ok{false};
    std::string body{};
    std::string reason{};
};

} // namespace merovingian::federation
