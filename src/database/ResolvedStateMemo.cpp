// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/database/ResolvedStateMemo.hpp"

#include <algorithm>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace merovingian::database
{

auto ResolvedStateMemo::rows_of(Entry const& entry) noexcept -> size_type
{
    return entry.sorted_group_ids.size() + entry.entries.size();
}

auto ResolvedStateMemo::find(std::string_view room_id, std::string_view context,
                             std::vector<std::string> const& sorted_group_ids) -> Entries const*
{
    auto const found = by_room_.find(room_id);
    if (found == by_room_.end() || found->second.context != context ||
        found->second.sorted_group_ids != sorted_group_ids)
    {
        return nullptr;
    }
    found->second.last_used = ++clock_;
    return &found->second.entries;
}

auto ResolvedStateMemo::forget_room(std::string_view room_id) -> void
{
    auto const found = by_room_.find(room_id);
    if (found == by_room_.end())
    {
        return;
    }
    rows_ -= rows_of(found->second);
    by_room_.erase(found);
}

auto ResolvedStateMemo::evict_least_recently_used() -> void
{
    auto const oldest = std::ranges::min_element(by_room_, {}, [](auto const& room) {
        return room.second.last_used;
    });
    if (oldest != by_room_.end())
    {
        rows_ -= rows_of(oldest->second);
        by_room_.erase(oldest);
    }
}

auto ResolvedStateMemo::remember(std::string_view room_id, std::string_view context,
                                 std::vector<std::string> sorted_group_ids, Entries entries) -> void
{
    forget_room(room_id);
    auto entry = Entry{std::string{context}, std::move(sorted_group_ids), std::move(entries), ++clock_};
    auto const rows = rows_of(entry);
    if (rows > max_rows)
    {
        return;
    }
    while (!by_room_.empty() && (by_room_.size() >= max_rooms || rows_ + rows > max_rows))
    {
        evict_least_recently_used();
    }
    by_room_.emplace(std::string{room_id}, std::move(entry));
    rows_ += rows;
}

auto ResolvedStateMemo::clear() noexcept -> void
{
    by_room_.clear();
    rows_ = 0U;
    clock_ = 0U;
}

} // namespace merovingian::database
