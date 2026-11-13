// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/database/StateBeforeMemo.hpp"

#include <iterator>
#include <utility>

namespace merovingian::database
{

auto StateBeforeMemo::key_of(std::string_view room_id, std::string_view context,
                             std::vector<std::string> const& sorted_group_ids) -> std::string
{
    // NUL never occurs in a room ID, a context or a group ID, so the parts cannot run into each other.
    auto key = std::string{room_id};
    key.push_back('\0');
    key.append(context);
    for (auto const& group_id : sorted_group_ids)
    {
        key.push_back('\0');
        key.append(group_id);
    }
    return key;
}

auto StateBeforeMemo::find(std::string_view room_id, std::string_view context,
                           std::vector<std::string> const& sorted_group_ids) const -> std::string const*
{
    auto const found = entries_.find(key_of(room_id, context, sorted_group_ids));
    return found == entries_.end() ? nullptr : &found->second.state_group_id;
}

auto StateBeforeMemo::remember(std::string_view room_id, std::string_view context,
                               std::vector<std::string> const& sorted_group_ids, std::string state_group_id) -> void
{
    auto key = key_of(room_id, context, sorted_group_ids);
    if (auto const existing = entries_.find(key); existing != entries_.end())
    {
        order_.erase(existing->second.sequence);
        entries_.erase(existing);
    }
    while (entries_.size() >= max_entries && !order_.empty())
    {
        auto const oldest = order_.begin();
        entries_.erase(oldest->second);
        order_.erase(oldest);
    }
    auto const sequence = next_sequence_++;
    order_.emplace(sequence, key);
    entries_.emplace(std::move(key), Entry{std::string{room_id}, std::move(state_group_id), sequence});
}

auto StateBeforeMemo::forget_room(std::string_view room_id) -> void
{
    for (auto entry = entries_.begin(); entry != entries_.end();)
    {
        if (entry->second.room_id == room_id)
        {
            order_.erase(entry->second.sequence);
            entry = entries_.erase(entry);
        }
        else
        {
            ++entry;
        }
    }
}

auto StateBeforeMemo::clear() noexcept -> void
{
    entries_.clear();
    order_.clear();
}

} // namespace merovingian::database
