// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/database/EventStateGroupTable.hpp"

#include "merovingian/database/StateGroupTableSupport.hpp"

#include <cstddef>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace merovingian::database
{

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
