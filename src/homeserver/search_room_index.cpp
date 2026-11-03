// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/search_room_index.hpp"

#include "merovingian/database/persistent_event.hpp"
#include "merovingian/database/persistent_store.hpp"

#include <algorithm>
#include <cstddef>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace merovingian::homeserver
{

SearchRoomIndex::SearchRoomIndex(database::PersistentStore const& store,
                                 std::unordered_set<std::string_view> const& rooms)
{
    if (rooms.empty())
    {
        return;
    }
    for (auto const room : rooms)
    {
        by_room_.try_emplace(std::string{room});
    }
    ++table_walks_;
    // in_stream_order() visits rows by ascending stream_ordering, so each room's list needs no sort.
    for (auto const& event : store.events.in_stream_order())
    {
        if (event.status == "rejected" || event.status == "soft_failed")
        {
            continue;
        }
        auto const found = by_room_.find(event.room_id);
        if (found != by_room_.end())
        {
            found->second.push_back(&event);
        }
    }
}

auto SearchRoomIndex::timeline(std::string_view room_id) const -> std::span<database::PersistentEvent const* const>
{
    // The map is keyed by std::string and has no transparent lookup, so the key is built once per call.
    auto const found = by_room_.find(std::string{room_id});
    if (found == by_room_.end())
    {
        return {};
    }
    return found->second;
}

auto SearchRoomIndex::position_of(database::PersistentEvent const& target) const -> std::optional<std::size_t>
{
    auto const rows = timeline(target.room_id);
    auto const first =
        std::ranges::lower_bound(rows, target.stream_ordering, {}, [](database::PersistentEvent const* row) noexcept {
            return row->stream_ordering;
        });
    // Rows may share a stream_ordering; the target is one of those at its own.
    for (auto it = first; it != rows.end() && (*it)->stream_ordering == target.stream_ordering; ++it)
    {
        if ((*it)->event_id == target.event_id)
        {
            return static_cast<std::size_t>(it - rows.begin());
        }
    }
    return std::nullopt;
}

} // namespace merovingian::homeserver
