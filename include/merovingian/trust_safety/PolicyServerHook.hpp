// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/trust_safety/EnforcementReason.hpp"
#include "merovingian/trust_safety/PolicyAction.hpp"

#include <cstdint>
#include <string>

namespace merovingian::trust_safety
{

struct PolicyServerHook final
{
    bool enabled{false};
    bool reachable{true};
    bool allow_without_result{false};
    bool decision_received{false};
    PolicyAction action{PolicyAction::allow};
    EnforcementReason reason{};
    std::string rule_id{};
    std::uint32_t timeout_milliseconds{250U};
};

} // namespace merovingian::trust_safety
