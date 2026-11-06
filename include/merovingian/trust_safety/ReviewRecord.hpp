// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/trust_safety/EnforcementReason.hpp"
#include "merovingian/trust_safety/policy_enums.hpp"

#include <string>

namespace merovingian::trust_safety
{

struct ReviewRecord final
{
    ReviewTarget target{ReviewTarget::media};
    std::string target_id{};
    bool active{false};
    EnforcementReason reason{};
};

} // namespace merovingian::trust_safety
