// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/Value.hpp"

#include <optional>
#include <string>

namespace merovingian::push
{

// One rule of a UserPushRules, as GET returns it. `conditions` is set for
// override and underride rules, `pattern` for content rules.
struct PushRuleEntry final
{
    std::string rule_id{};
    bool is_default{false};
    bool enabled{true};
    canonicaljson::Array actions{};
    std::optional<canonicaljson::Array> conditions{};
    std::optional<std::string> pattern{};
};

} // namespace merovingian::push
