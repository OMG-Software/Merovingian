// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string_view>

namespace merovingian::sync
{

// Whether `event_type` matches a filter `types` / `not_types` entry.
//
// Spec: Matrix CS API v1.19 § Filtering ("A `*` can be used as a wildcard to match any sequence of
// characters"). `*` may appear anywhere in `pattern`, any number of times, and stands for any run of
// characters, the empty run included. A pattern without `*` is an exact match.
//
// Both arguments are attacker-controlled. The match is iterative: no recursion, no regex, no allocation
// and no backtracking over earlier stars, so no input makes it exponential. With n = event_type.size()
// and m = pattern.size() it does at most O((n + m) * s) character comparisons, where s is the longest
// run between two stars (O(n + m) for a pattern whose runs are short).
[[nodiscard]] auto type_pattern_matches(std::string_view pattern, std::string_view event_type) noexcept -> bool;

} // namespace merovingian::sync
