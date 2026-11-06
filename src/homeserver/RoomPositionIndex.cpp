// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/RoomPositionIndex.hpp"

#include <algorithm>
#include <cstddef>
#include <iterator>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::homeserver
{

auto RoomPositionIndex::find(std::vector<LocalRoom> const& rooms, std::string_view room_id) const
    -> std::optional<std::size_t>
{
    auto const lock = std::scoped_lock{mutex_};
    if (indexed_rows_ == rooms.size())
    {
        auto const found = positions_.find(std::string{room_id});
        if (found != positions_.end() && found->second < rooms.size() && rooms[found->second].room_id == room_id)
        {
            return found->second;
        }
    }
    // A miss, a mismatch or an index out of step: the scan is the answer, and a room it finds means the index was
    // stale.
    auto const scanned = std::ranges::find_if(rooms, [room_id](LocalRoom const& room) {
        return room.room_id == room_id;
    });
    if (scanned == rooms.end())
    {
        return std::nullopt;
    }
    positions_.clear();
    positions_.reserve(rooms.size());
    for (auto position = std::size_t{0U}; position < rooms.size(); ++position)
    {
        positions_.try_emplace(rooms[position].room_id, position);
    }
    indexed_rows_ = rooms.size();
    return static_cast<std::size_t>(std::distance(rooms.begin(), scanned));
}

} // namespace merovingian::homeserver
