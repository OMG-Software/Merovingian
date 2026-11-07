// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/push/PushRule.hpp"

#include <vector>

namespace merovingian::push
{

// A user's full push ruleset, split by kind in spec precedence order.
struct PushRuleset final
{
    std::vector<PushRule> override_rules{};
    std::vector<PushRule> content_rules{};
    std::vector<PushRule> room_rules{};
    std::vector<PushRule> sender_rules{};
    std::vector<PushRule> underride_rules{};
};

} // namespace merovingian::push
