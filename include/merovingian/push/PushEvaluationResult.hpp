// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace merovingian::push
{

// Resolved outcome of evaluating one event against one ruleset.
// `matched_rule_id` is empty when no rule matched (the spec's "the
// homeserver MUST NOT notify the Push Gateway for that event" case); in that
// case `notify` is always false.
struct PushEvaluationResult final
{
    bool notify{false};
    std::optional<std::string> tweak_sound{};
    bool tweak_highlight{false};
    std::string matched_rule_id{};
    // The glob-matching steps this evaluation spent on `content.body`, and whether it ran out of
    // its budget (ADR-0343). When it did, a glob that needed more did not match, so the caller
    // may want to log it; the result is otherwise as for any evaluation.
    std::uint64_t glob_steps_used{0U};
    bool glob_budget_exhausted{false};
};

} // namespace merovingian::push
