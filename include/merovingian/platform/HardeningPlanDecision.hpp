// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::platform
{

struct HardeningPlanDecision final
{
    bool accepted{false};
    bool fail_closed{true};
    std::string reason{};
};

} // namespace merovingian::platform
