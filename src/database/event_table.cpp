// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/database/event_table.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <limits>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace merovingian::database
{

auto EventTable::find(std::string_view event_id) const -> const_iterator
{
    auto const entry = by_id_.find(event_id);
    if (entry == by_id_.end())
    {
        return rows_.end();
    }
    return rows_.begin() + static_cast<std::ptrdiff_t>(entry->second);
}

auto EventTable::contains(std::string_view event_id) const -> bool
{
    return by_id_.contains(event_id);
}

auto EventTable::find_in_room(std::string_view room_id, std::string_view event_id) const -> const_iterator
{
    auto const event = find(event_id);
    return event != rows_.end() && event->room_id == room_id ? event : rows_.end();
}

auto EventTable::insert(PersistentEvent event) -> bool
{
    if (by_id_.contains(event.event_id))
    {
        return false;
    }
    auto const position = rows_.size();
    auto const stream_ordering = event.stream_ordering;
    by_id_.emplace(event.event_id, position);
    rows_.push_back(std::move(event));

    // The common case: the newest event so far goes on the end of the stream order.
    if (stream_order_.empty() || rows_[stream_order_.back()].stream_ordering <= stream_ordering)
    {
        stream_order_.push_back(position);
        return true;
    }
    // An event that committed after a newer one: after every row with a stream_ordering no greater
    // than its own, so equal stream orderings stay in the order they were added.
    auto const after = std::ranges::upper_bound(stream_order_, stream_ordering, {}, [this](std::size_t held) {
        return rows_[held].stream_ordering;
    });
    stream_order_.insert(after, position);
    return true;
}

auto EventTable::insert_all(std::vector<PersistentEvent> events) -> std::size_t
{
    auto const first_added = rows_.size();
    rows_.reserve(rows_.size() + events.size());
    by_id_.reserve(by_id_.size() + events.size());
    for (auto& event : events)
    {
        if (by_id_.contains(event.event_id))
        {
            continue;
        }
        by_id_.emplace(event.event_id, rows_.size());
        rows_.push_back(std::move(event));
    }

    // Positions of the added rows go on the end in ascending order; a stable sort of that tail and a
    // stable merge with the existing order keep equal stream orderings in the order they were added.
    auto const held = static_cast<std::ptrdiff_t>(stream_order_.size());
    stream_order_.reserve(rows_.size());
    for (auto position = first_added; position < rows_.size(); ++position)
    {
        stream_order_.push_back(position);
    }
    auto const stream_ordering_of = [this](std::size_t position) {
        return rows_[position].stream_ordering;
    };
    std::ranges::stable_sort(stream_order_.begin() + held, stream_order_.end(), {}, stream_ordering_of);
    std::ranges::inplace_merge(stream_order_, stream_order_.begin() + held, {}, stream_ordering_of);
    return rows_.size() - first_added;
}

auto EventTable::erase_marked(std::vector<bool> const& removed) -> std::size_t
{
    // Old position -> position after removal; `gone` for a removed row.
    constexpr auto gone = std::numeric_limits<std::size_t>::max();
    auto remap = std::vector<std::size_t>(rows_.size(), gone);
    auto kept = std::size_t{0U};
    for (auto position = std::size_t{0U}; position < rows_.size(); ++position)
    {
        if (removed[position])
        {
            continue;
        }
        if (kept != position)
        {
            rows_[kept] = std::move(rows_[position]);
        }
        remap[position] = kept;
        ++kept;
    }
    auto const removed_count = rows_.size() - kept;
    rows_.resize(kept);

    std::erase_if(by_id_, [&remap](auto const& entry) {
        return remap[entry.second] == gone;
    });
    for (auto& entry : by_id_)
    {
        entry.second = remap[entry.second];
    }

    // Removing rows does not change the relative order of the rest, so the surviving positions are
    // already in stream order once renumbered.
    std::erase_if(stream_order_, [&remap](std::size_t position) {
        return remap[position] == gone;
    });
    for (auto& position : stream_order_)
    {
        position = remap[position];
    }
    return removed_count;
}

auto EventTable::extract() -> std::vector<PersistentEvent>
{
    auto rows = std::move(rows_);
    clear();
    return rows;
}

auto EventTable::clear() noexcept -> void
{
    rows_.clear();
    by_id_.clear();
    stream_order_.clear();
}

auto EventTable::reserve(size_type capacity) -> void
{
    rows_.reserve(capacity);
    by_id_.reserve(capacity);
    stream_order_.reserve(capacity);
}

} // namespace merovingian::database
