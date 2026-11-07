// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <optional>
#include <string>

namespace merovingian::push
{

// Where PUT places a rule: `before` and `after` are the query parameters of the
// same name. When both are given, `before` decides (spec: "the new or updated
// rule must be the next most important rule with respect to the rule
// identified by before").
struct PushRulePlacement final
{
    std::optional<std::string> before{};
    std::optional<std::string> after{};
};

} // namespace merovingian::push
