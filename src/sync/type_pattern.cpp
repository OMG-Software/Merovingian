// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/sync/type_pattern.hpp"

#include <string_view>

namespace merovingian::sync
{

auto type_pattern_matches(std::string_view pattern, std::string_view event_type) noexcept -> bool
{
    auto const first_star = pattern.find('*');
    if (first_star == std::string_view::npos)
    {
        return pattern == event_type;
    }
    // The text before the first star must open the type, and the text after the last star must close it.
    // Checking the head before the tail leaves no overlap between them.
    if (!event_type.starts_with(pattern.substr(0U, first_star)))
    {
        return false;
    }
    event_type.remove_prefix(first_star);
    pattern.remove_prefix(first_star);
    auto const tail = pattern.substr(pattern.rfind('*') + 1U);
    if (!event_type.ends_with(tail))
    {
        return false;
    }
    event_type.remove_suffix(tail.size());
    pattern.remove_suffix(tail.size());

    // What remains of the pattern starts and ends with a star. Each run between stars is found at its
    // leftmost occurrence after the previous one; taking the leftmost leaves the most text for the later
    // runs, so a run that cannot be found there cannot be found anywhere.
    while (!pattern.empty())
    {
        if (pattern.front() == '*')
        {
            pattern.remove_prefix(1U);
            continue;
        }
        auto const run = pattern.substr(0U, pattern.find('*'));
        auto const at = event_type.find(run);
        if (at == std::string_view::npos)
        {
            return false;
        }
        event_type.remove_prefix(at + run.size());
        pattern.remove_prefix(run.size());
    }
    return true;
}

} // namespace merovingian::sync
