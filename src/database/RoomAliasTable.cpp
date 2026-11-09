// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/database/RoomAliasTable.hpp"

#include "merovingian/database/PersistentRoomAlias.hpp"

#include <algorithm>
#include <cstddef>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace merovingian::database
{

auto RoomAliasTable::find(std::string_view alias) const -> PersistentRoomAlias const*
{
    auto const found = by_alias_.find(alias);
    return found == by_alias_.end() ? nullptr : &rows_[found->second];
}

auto RoomAliasTable::contains(std::string_view alias) const -> bool
{
    return by_alias_.contains(alias);
}

auto RoomAliasTable::aliases_of_room(std::string_view room_id) const -> std::vector<std::string>
{
    auto aliases = std::vector<std::string>{};
    auto const found = by_room_.find(room_id);
    if (found == by_room_.end())
    {
        return aliases;
    }
    aliases.reserve(found->second.size());
    for (auto const position : found->second)
    {
        aliases.push_back(rows_[position].room_alias);
    }
    return aliases;
}

auto RoomAliasTable::count_for_room(std::string_view room_id) const -> size_type
{
    auto const found = by_room_.find(room_id);
    return found == by_room_.end() ? size_type{0U} : found->second.size();
}

auto RoomAliasTable::count_for_creator(std::string_view creator_user_id) const -> size_type
{
    auto const found = by_creator_.find(creator_user_id);
    return found == by_creator_.end() ? size_type{0U} : found->second;
}

auto RoomAliasTable::index_room(std::string_view room_id, std::size_t position) -> void
{
    if (auto const found = by_room_.find(room_id); found != by_room_.end())
    {
        found->second.push_back(position);
        return;
    }
    by_room_.emplace(std::string{room_id}, std::vector<std::size_t>{position});
}

auto RoomAliasTable::unindex_room(std::string_view room_id, std::size_t position) -> void
{
    auto const found = by_room_.find(room_id);
    if (found == by_room_.end())
    {
        return;
    }
    std::erase(found->second, position);
    if (found->second.empty())
    {
        by_room_.erase(found);
    }
}

auto RoomAliasTable::count_creator(std::string_view creator_user_id, bool added) -> void
{
    if (creator_user_id.empty())
    {
        return;
    }
    auto const found = by_creator_.find(creator_user_id);
    if (added)
    {
        if (found == by_creator_.end())
        {
            by_creator_.emplace(std::string{creator_user_id}, size_type{1U});
        }
        else
        {
            ++found->second;
        }
        return;
    }
    if (found != by_creator_.end() && --found->second == 0U)
    {
        by_creator_.erase(found);
    }
}

auto RoomAliasTable::insert(PersistentRoomAlias alias) -> bool
{
    if (by_alias_.contains(alias.room_alias))
    {
        return false;
    }
    auto const position = rows_.size();
    by_alias_.emplace(alias.room_alias, position);
    index_room(alias.room_id, position);
    count_creator(alias.creator_user_id, true);
    rows_.push_back(std::move(alias));
    return true;
}

auto RoomAliasTable::erase(std::string_view alias) -> bool
{
    auto const found = by_alias_.find(alias);
    if (found == by_alias_.end())
    {
        return false;
    }
    auto const position = found->second;
    by_alias_.erase(found);
    unindex_room(rows_[position].room_id, position);
    count_creator(rows_[position].creator_user_id, false);

    auto const last = rows_.size() - 1U;
    if (position != last)
    {
        // Swap-and-pop: the last row fills the hole, and its two indexes follow it.
        rows_[position] = std::move(rows_[last]);
        if (auto const moved_alias = by_alias_.find(rows_[position].room_alias); moved_alias != by_alias_.end())
        {
            moved_alias->second = position;
        }
        if (auto const moved_room = by_room_.find(rows_[position].room_id); moved_room != by_room_.end())
        {
            std::ranges::replace(moved_room->second, last, position);
        }
    }
    rows_.pop_back();
    return true;
}

auto RoomAliasTable::reassign(std::string_view alias, std::string_view room_id) -> bool
{
    auto const found = by_alias_.find(alias);
    if (found == by_alias_.end())
    {
        return false;
    }
    auto const position = found->second;
    if (rows_[position].room_id == room_id)
    {
        return true;
    }
    unindex_room(rows_[position].room_id, position);
    rows_[position].room_id = std::string{room_id};
    index_room(rows_[position].room_id, position);
    return true;
}

auto RoomAliasTable::clear() noexcept -> void
{
    rows_.clear();
    by_alias_.clear();
    by_room_.clear();
    by_creator_.clear();
}

} // namespace merovingian::database
