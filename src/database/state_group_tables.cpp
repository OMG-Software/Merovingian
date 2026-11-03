// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/database/state_group_tables.hpp"

#include <cstddef>
#include <iterator>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace merovingian::database
{

// StateGroupTable

auto StateGroupTable::find(std::string_view state_group_id) const -> const_iterator
{
    auto const found = by_id_.find(state_group_id);
    return found == by_id_.end() ? rows_.end() : rows_.begin() + static_cast<std::ptrdiff_t>(found->second);
}

auto StateGroupTable::contains(std::string_view state_group_id) const -> bool
{
    return by_id_.contains(state_group_id);
}

auto StateGroupTable::insert(PersistentStateGroup group) -> bool
{
    if (by_id_.contains(group.state_group_id))
    {
        return false;
    }
    by_id_.emplace(group.state_group_id, rows_.size());
    rows_.push_back(std::move(group));
    return true;
}

auto StateGroupTable::insert_all(std::vector<PersistentStateGroup> groups) -> std::size_t
{
    auto added = std::size_t{0U};
    rows_.reserve(rows_.size() + groups.size());
    for (auto& group : groups)
    {
        added += insert(std::move(group)) ? 1U : 0U;
    }
    return added;
}

auto StateGroupTable::erase_marked(std::vector<bool> const& removed) -> std::size_t
{
    auto const before = rows_.size();
    auto const remap = detail::compact_unmarked(rows_, removed);
    std::erase_if(by_id_, [&remap](auto& item) {
        item.second = remap[item.second];
        return item.second == detail::removed_position;
    });
    return before - rows_.size();
}

auto StateGroupTable::clear() noexcept -> void
{
    rows_.clear();
    by_id_.clear();
}

// StateGroupEntryTable

auto StateGroupEntryTable::count_of(std::string_view state_group_id) const -> std::size_t
{
    auto const found = by_group_.find(state_group_id);
    return found == by_group_.end() ? std::size_t{0U} : found->second.size();
}

auto StateGroupEntryTable::insert(PersistentStateGroupStateEntry entry) -> void
{
    auto const position = rows_.size();
    auto const found = by_group_.find(entry.state_group_id);
    if (found != by_group_.end())
    {
        found->second.push_back(position);
    }
    else
    {
        by_group_.emplace(entry.state_group_id, std::vector<std::size_t>{position});
    }
    rows_.push_back(std::move(entry));
}

auto StateGroupEntryTable::insert_all(std::vector<PersistentStateGroupStateEntry> entries) -> void
{
    rows_.reserve(rows_.size() + entries.size());
    for (auto& entry : entries)
    {
        insert(std::move(entry));
    }
}

auto StateGroupEntryTable::erase_marked(std::vector<bool> const& removed) -> std::size_t
{
    auto const before = rows_.size();
    auto const remap = detail::compact_unmarked(rows_, removed);
    std::erase_if(by_group_, [&remap](auto& item) {
        auto& positions = item.second;
        auto kept = std::size_t{0U};
        for (auto const position : positions)
        {
            if (remap[position] != detail::removed_position)
            {
                positions[kept] = remap[position];
                ++kept;
            }
        }
        positions.resize(kept);
        return positions.empty();
    });
    return before - rows_.size();
}

auto StateGroupEntryTable::clear() noexcept -> void
{
    rows_.clear();
    by_group_.clear();
}

// EventStateGroupTable

auto EventStateGroupTable::state_group_of(std::string_view event_id) const -> std::optional<std::string_view>
{
    auto const found = by_event_.find(event_id);
    if (found == by_event_.end())
    {
        return std::nullopt;
    }
    return std::string_view{rows_[found->second].state_group_id};
}

auto EventStateGroupTable::contains(std::string_view event_id) const -> bool
{
    return by_event_.contains(event_id);
}

auto EventStateGroupTable::assign(std::string_view event_id, std::string_view state_group_id) -> void
{
    if (auto const found = by_event_.find(event_id); found != by_event_.end())
    {
        rows_[found->second].state_group_id = std::string{state_group_id};
        return;
    }
    by_event_.emplace(std::string{event_id}, rows_.size());
    rows_.push_back({std::string{event_id}, std::string{state_group_id}});
}

auto EventStateGroupTable::insert_all(std::vector<PersistentEventStateGroup> mappings) -> void
{
    rows_.reserve(rows_.size() + mappings.size());
    for (auto const& mapping : mappings)
    {
        assign(mapping.event_id, mapping.state_group_id);
    }
}

auto EventStateGroupTable::erase_marked(std::vector<bool> const& removed) -> std::size_t
{
    auto const before = rows_.size();
    auto const remap = detail::compact_unmarked(rows_, removed);
    std::erase_if(by_event_, [&remap](auto& item) {
        item.second = remap[item.second];
        return item.second == detail::removed_position;
    });
    return before - rows_.size();
}

auto EventStateGroupTable::clear() noexcept -> void
{
    rows_.clear();
    by_event_.clear();
}

} // namespace merovingian::database
