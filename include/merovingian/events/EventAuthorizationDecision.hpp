// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::events
{

struct EventAuthorizationDecision final
{
    bool allowed{false};
    std::string rule_hook{};
    std::string rule_step{};
    std::string reason{};
};

} // namespace merovingian::events
