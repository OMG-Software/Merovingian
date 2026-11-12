// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::push
{

// The most matcher steps one evaluation (one recipient, one event) spends on `content.body`
// globs, summed over every rule: content rules and `event_match` conditions on `content.body`.
// The sender chooses the body and the recipient the patterns, so without it their product, times
// the rule count, is spent under `runtime.mutex` (ADR-0343).
inline constexpr std::uint64_t max_push_glob_steps_per_evaluation = std::uint64_t{1U} << 21U;

// The work evaluations may spend on matching globs, across every rule they run (ADR-0343, ADR-0607). One step is
// one turn of a matcher's inner loops. Past the budget a glob does not match and `exhausted` is set. A caller that
// runs many evaluations for one request lends them all one budget (the push badge of one event, C15, ADR-0722), so
// the work is bounded by a constant instead of by the number of evaluations.
struct PushEvaluationBudget final
{
    std::uint64_t remaining{max_push_glob_steps_per_evaluation};
    std::uint64_t spent{0U};
    bool exhausted{false};

    // Takes `steps` from the budget; false (and exhausted) when it holds fewer.
    [[nodiscard]] auto charge(std::uint64_t steps) noexcept -> bool
    {
        if (steps > remaining)
        {
            exhausted = true;
            return false;
        }
        remaining -= steps;
        spent += steps;
        return true;
    }
};

} // namespace merovingian::push
