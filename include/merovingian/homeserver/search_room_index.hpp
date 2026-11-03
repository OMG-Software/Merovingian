// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/persistent_event.hpp"
#include "merovingian/database/persistent_store.hpp"

#include <cstddef>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace merovingian::homeserver
{

// The timeline of each of a set of rooms, in ascending stream order, built for one POST /search request that
// asked for `event_context` (security audit run 2, F-31; ADR-0333). The old context builder walked every
// row of the events table and sorted the room's rows once per match, so a page of 100 matches cost 100
// walks under `runtime.mutex`. This walks the table once for however many rooms and matches there are, and
// finds a match in its room by binary search on `stream_ordering`.
//
// A rejected or soft-failed event is left out, as GET /context leaves it out (ADR-0064). Valid until the
// store is next changed; build it and use it within one request, with `runtime.mutex` held.
class SearchRoomIndex final
{
public:
    // One pass over the store's events when `rooms` is not empty, none otherwise.
    SearchRoomIndex(database::PersistentStore const& store, std::unordered_set<std::string_view> const& rooms);

    // The room's timeline rows by ascending stream_ordering; empty for a room that was not asked for.
    [[nodiscard]] auto timeline(std::string_view room_id) const -> std::span<database::PersistentEvent const* const>;

    // The index of `target` in its room's timeline, or nullopt when it is not there.
    [[nodiscard]] auto position_of(database::PersistentEvent const& target) const -> std::optional<std::size_t>;

    // How many times the whole events table was walked: 0 or 1, however many rooms and matches.
    [[nodiscard]] auto table_walks() const noexcept -> std::size_t
    {
        return table_walks_;
    }

private:
    std::unordered_map<std::string, std::vector<database::PersistentEvent const*>> by_room_;
    std::size_t table_walks_{0U};
};

} // namespace merovingian::homeserver
