// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/database/StateGroupTable.hpp"

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

} // namespace merovingian::database
