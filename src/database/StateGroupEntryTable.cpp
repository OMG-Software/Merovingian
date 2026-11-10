// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/database/StateGroupEntryTable.hpp"

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

} // namespace merovingian::database
