// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/trust_safety/EnforcementReason.hpp"
#include "merovingian/trust_safety/PolicyAction.hpp"
#include "merovingian/trust_safety/PolicySurface.hpp"

#include <string>

namespace merovingian::trust_safety
{

struct SafetyAuditEvent final
{
    std::string event_type{};
    std::string actor{};
    std::string entity{};
    PolicySurface surface{PolicySurface::account};
    PolicyAction action{PolicyAction::deny};
    EnforcementReason reason{};
};

} // namespace merovingian::trust_safety
