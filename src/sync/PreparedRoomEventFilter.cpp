// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/sync/PreparedRoomEventFilter.hpp"

#include "merovingian/sync/RoomFilter.hpp"
#include "merovingian/sync/type_pattern.hpp"

#include <algorithm>
#include <iterator>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace merovingian::sync
{

namespace
{

    auto fill_set(std::vector<std::string> const& list, auto& set) -> void
    {
        set.reserve(list.size());
        for (auto const& entry : list)
        {
            set.insert(entry);
        }
    }

} // namespace

PreparedRoomEventFilter::TypePatterns::TypePatterns(std::vector<std::string> const& patterns)
    : any{!patterns.empty()}
{
    // A pattern whose only '*' is its last character (the bare "*" included) matches every type that starts
    // with the rest of it; a pattern with no '*' is an exact type. A '*' anywhere else makes it a general
    // glob, kept whole and judged by type_pattern_matches, the matcher event_passes_filter uses, so the two
    // agree on every pattern.
    for (auto const& pattern : patterns)
    {
        auto const star = pattern.find('*');
        if (star == std::string::npos)
        {
            exact.insert(pattern);
        }
        else if (star == pattern.size() - 1U)
        {
            prefixes.push_back(pattern.substr(0U, star));
        }
        else
        {
            globs.push_back(pattern);
        }
    }
    std::ranges::sort(prefixes);
    // In sorted order every string between a prefix and a string it starts is itself started by it, so a
    // prefix is covered exactly when it starts with the last one kept.
    auto kept = std::vector<std::string>{};
    for (auto& prefix : prefixes)
    {
        if (kept.empty() || !std::string_view{prefix}.starts_with(kept.back()))
        {
            kept.push_back(std::move(prefix));
        }
    }
    prefixes = std::move(kept);
}

auto PreparedRoomEventFilter::TypePatterns::matches(std::string_view event_type) const noexcept -> bool
{
    if (exact.contains(event_type))
    {
        return true;
    }
    // Each glob costs O(n * s) (type_pattern_matches); only patterns with an interior '*' land here.
    if (std::ranges::any_of(globs, [event_type](std::string const& glob) noexcept {
            return type_pattern_matches(glob, event_type);
        }))
    {
        return true;
    }
    // No kept prefix starts another, so only the greatest one at or before the type can start it.
    auto const after = std::ranges::upper_bound(prefixes, event_type, {}, [](std::string const& prefix) noexcept {
        return std::string_view{prefix};
    });
    return after != prefixes.begin() && event_type.starts_with(std::string_view{*std::prev(after)});
}

PreparedRoomEventFilter::PreparedRoomEventFilter(RoomFilter const& filter)
    : types_{filter.timeline.types}
    , not_types_{filter.timeline.not_types}
{
    fill_set(filter.rooms, rooms_);
    fill_set(filter.not_rooms, not_rooms_);
    fill_set(filter.timeline.senders, senders_);
    fill_set(filter.timeline.not_senders, not_senders_);
}

auto PreparedRoomEventFilter::room_passes(std::string_view room_id) const noexcept -> bool
{
    if (!rooms_.empty() && !rooms_.contains(room_id))
    {
        return false;
    }
    return not_rooms_.empty() || !not_rooms_.contains(room_id);
}

auto PreparedRoomEventFilter::event_passes(std::string_view event_type, std::string_view sender) const noexcept -> bool
{
    // As event_passes_filter: with no event type the type lists are skipped, the sender lists still apply.
    if (!event_type.empty())
    {
        if (types_.any && !types_.matches(event_type))
        {
            return false;
        }
        if (not_types_.any && not_types_.matches(event_type))
        {
            return false;
        }
    }
    if (!senders_.empty() && !senders_.contains(sender))
    {
        return false;
    }
    return not_senders_.empty() || !not_senders_.contains(sender);
}

} // namespace merovingian::sync
