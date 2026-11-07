// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/push/PushCondition.hpp"
#include "merovingian/push/PushRuleKind.hpp"

#include <optional>
#include <string>
#include <vector>

namespace merovingian::push
{

// A single parsed push rule. `content_pattern` is populated only for
// `PushRuleKind::content` rules (the rule's own `pattern` field, matched
// against `content.body`); `conditions` is populated only for `override` and
// `underride` rules. `room` and `sender` rules match implicitly via
// `rule_id` (the room ID / sender's user ID respectively) and use neither.
//
// The action outcome is pre-resolved at parse time rather than kept as a raw
// actions array: `notify` is true iff the rule's `actions` array contains the
// `"notify"` string action (the historical `dont_notify`/`coalesce` actions
// are ignored, per spec, exactly as an empty actions array would be).
// `tweak_sound` and `tweak_highlight` mirror the `set_tweak` actions the
// default ruleset and Matrix v1.19 both define.
struct PushRule final
{
    std::string rule_id{};
    PushRuleKind kind{PushRuleKind::override_kind};
    bool enabled{true};
    bool is_default{false};
    std::vector<PushCondition> conditions{};
    std::string content_pattern{};
    bool notify{false};
    std::optional<std::string> tweak_sound{};
    bool tweak_highlight{false};
};

} // namespace merovingian::push
