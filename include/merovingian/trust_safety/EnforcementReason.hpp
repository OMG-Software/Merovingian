// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::trust_safety
{

struct EnforcementReason final
{
    std::string code{};
    std::string public_summary{};
    std::string admin_detail{};
    bool admin_visible{true};
};

} // namespace merovingian::trust_safety
