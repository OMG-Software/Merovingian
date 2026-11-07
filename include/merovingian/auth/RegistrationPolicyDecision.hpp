// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::auth
{

struct RegistrationPolicyDecision final
{
    bool allowed{false};
    std::string reason{};
};

} // namespace merovingian::auth
