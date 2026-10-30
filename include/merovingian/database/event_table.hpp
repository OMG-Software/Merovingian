// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/persistent_event.hpp"

#include <algorithm>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <ranges>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace merovingian::database
{

// The most rows one nearest_by_time() search offers its filter, so a lookup stepping over rows the
// asker may not see stays bounded however a room's history is spread (ADR-0300).
inline constexpr std::size_t max_time_search_examined{1000U};

// Which way nearest_by_time() looks from a timestamp (Client-Server API,
// `GET /rooms/{roomId}/timestamp_to_event`, `dir`: `f` forwards, `b` backwards).
enum class TimeDirection : unsigned char
{
    forwards,
    backwards,
};

// The in-memory mirror of the `events` table (ADR-0215). It owns the rows and keeps three indexes
// over them, so every writer keeps them consistent by construction:
//
//   - by event ID: find() is a hash lookup, not a scan of every stored event;
//   - by stream order: in_stream_order() visits rows by ascending stream_ordering (rows with equal
//     stream_ordering in the order they were added), whatever order they arrived in;
//   - by room and time (ADR-0300): nearest_by_time() seeks the row nearest an `origin_server_ts` in
//     one room by binary search. The key is (origin_server_ts, depth, stream_ordering). A row is in
//     this index only while it is a timeline event: its status is not `outlier`, `rejected` or
//     `soft_failed`, and its JSON carries an integer top-level `origin_server_ts`. modify() moves a
//     row in or out when a mutation changes that.
//
// Iterating the table itself visits rows in the order they were added, which is NOT stream order:
// hydration selects with no ORDER BY, PostgreSQL moves a row whose status is updated, and stream
// orderings commit out of order across rooms. Both indexes hold positions in the row vector, never
// iterators or pointers, so they survive its reallocation.
//
// Rows are read-only through the table except through modify(), which cannot change the two
// fields the first two indexes are keyed on. An event ID is held at most once, as it is the table's primary key on
// disk. The table has no lock of its own: it is guarded by whatever guards the PersistentStore that owns it
// (`runtime.mutex` in the homeserver).
class EventTable final
{
public:
    using value_type = PersistentEvent;
    using size_type = std::size_t;
    using const_iterator = std::vector<PersistentEvent>::const_iterator;
    using iterator = const_iterator;

    // Rows in the order they were added.
    [[nodiscard]] auto begin() const noexcept -> const_iterator
    {
        return rows_.begin();
    }
    [[nodiscard]] auto end() const noexcept -> const_iterator
    {
        return rows_.end();
    }
    [[nodiscard]] auto size() const noexcept -> size_type
    {
        return rows_.size();
    }
    [[nodiscard]] auto empty() const noexcept -> bool
    {
        return rows_.empty();
    }
    [[nodiscard]] auto operator[](size_type position) const -> PersistentEvent const&
    {
        return rows_[position];
    }
    [[nodiscard]] auto front() const -> PersistentEvent const&
    {
        return rows_.front();
    }
    [[nodiscard]] auto back() const -> PersistentEvent const&
    {
        return rows_.back();
    }
    [[nodiscard]] auto rows() const noexcept -> std::vector<PersistentEvent> const&
    {
        return rows_;
    }

    // The row whose event ID is `event_id`, or end().
    [[nodiscard]] auto find(std::string_view event_id) const -> const_iterator;
    [[nodiscard]] auto contains(std::string_view event_id) const -> bool;
    // The rows whose event ID is `event_id`: none or one. For a loop whose body runs for the match.
    [[nodiscard]] auto with_id(std::string_view event_id) const -> std::ranges::subrange<const_iterator>;
    // The row whose event ID is `event_id` if it is in room `room_id`, otherwise end().
    [[nodiscard]] auto find_in_room(std::string_view room_id, std::string_view event_id) const -> const_iterator;

    // Every row by ascending stream_ordering; rows with equal stream_ordering in the order they were
    // added. Valid until the table is next changed. std::views::reverse gives newest first.
    [[nodiscard]] auto in_stream_order() const
    {
        return std::views::transform(stream_order_, [this](std::size_t position) -> PersistentEvent const& {
            return rows_[position];
        });
    }

    // The row nearest `ts` in room `room_id`, looking `direction` from it, that `accept` takes:
    // forwards, the first row in (origin_server_ts, depth, stream_ordering) order with
    // origin_server_ts >= ts; backwards, the last with origin_server_ts <= ts (the boundary is
    // inclusive both ways). Rows `accept` refuses are stepped over, and at most `max_examined` rows
    // are offered to it, so the cost is O(log n + max_examined) however the room's rows are spread.
    // `accept` is called as accept(PersistentEvent const&) -> bool. `event` is end() when no row
    // qualified; `truncated` is then true when the search stopped at `max_examined` with candidates
    // left, so "none" means only "none within the cap". Valid until the table is next changed.
    struct NearestByTime final
    {
        const_iterator event;
        bool truncated{false};
    };
    template <typename Accept>
    [[nodiscard]] auto nearest_by_time(std::string_view room_id, std::int64_t ts, TimeDirection direction,
                                       Accept accept, std::size_t max_examined) const -> NearestByTime
    {
        auto const room = by_room_time_.find(room_id);
        if (room == by_room_time_.end())
        {
            return {rows_.end(), false};
        }
        auto const& entries = room->second;
        auto const at = [this](TimeEntry const& entry) {
            return rows_.begin() + static_cast<std::ptrdiff_t>(entry.position);
        };
        auto examined = std::size_t{0U};
        if (direction == TimeDirection::forwards)
        {
            auto it = std::ranges::lower_bound(entries, ts, {}, &TimeEntry::origin_server_ts);
            for (; it != entries.end(); ++it)
            {
                if (examined == max_examined)
                {
                    return {rows_.end(), true};
                }
                ++examined;
                if (std::invoke(accept, *at(*it)))
                {
                    return {at(*it), false};
                }
            }
            return {rows_.end(), false};
        }
        auto it = std::ranges::upper_bound(entries, ts, {}, &TimeEntry::origin_server_ts);
        while (it != entries.begin())
        {
            if (examined == max_examined)
            {
                return {rows_.end(), true};
            }
            ++examined;
            --it;
            if (std::invoke(accept, *at(*it)))
            {
                return {at(*it), false};
            }
        }
        return {rows_.end(), false};
    }

    // Adds `event` unless a row with its event ID is already held; returns whether it was added.
    // Costs a hash insert plus, for an event older than the newest held, a shift of the stream-order
    // positions after it (8 bytes each); the rows themselves never move.
    [[nodiscard]] auto insert(PersistentEvent event) -> bool;
    // insert() under the name the call sites that held `events` as a std::vector use.
    auto push_back(PersistentEvent event) -> bool
    {
        return insert(std::move(event));
    }
    // Adds every event whose ID is not already held (a repeated ID keeps its first row) and sorts
    // their stream order in one pass instead of one shift per row: the hydration and room-reload
    // path. Returns how many were added.
    auto insert_all(std::vector<PersistentEvent> events) -> std::size_t;

    // Removes every row `predicate` accepts and repairs both indexes in one linear pass, without
    // rehashing the remaining IDs. Returns how many were removed.
    template <typename Predicate>
    auto erase_if(Predicate predicate) -> std::size_t
    {
        auto removed = std::vector<bool>(rows_.size(), false);
        auto any = false;
        for (auto position = std::size_t{0U}; position < rows_.size(); ++position)
        {
            removed[position] = std::invoke(predicate, std::as_const(rows_[position]));
            any = any || removed[position];
        }
        return any ? erase_marked(removed) : std::size_t{0U};
    }

    // Applies `mutation` to the row at `row`, an iterator from this table. The indexes are keyed on
    // event_id and stream_ordering, so those two fields are put back if the mutation changes them:
    // a row cannot be renamed or moved in stream order in place.
    template <typename Mutation>
    auto modify(const_iterator row, Mutation mutation) -> void
    {
        auto const position = static_cast<std::size_t>(row - rows_.cbegin());
        auto& target = rows_[position];
        auto event_id = target.event_id;
        auto const stream_ordering = target.stream_ordering;
        // The room-and-time key follows the row's room, depth, status and JSON, which a mutation may
        // change, so it is taken before and after.
        auto room_id = target.room_id;
        auto const time_before = time_entry_for(target, position);
        std::invoke(mutation, target);
        target.event_id = std::move(event_id);
        target.stream_ordering = stream_ordering;
        if (target.room_id != room_id || time_entry_for(target, position) != time_before)
        {
            unindex_time(room_id, time_before);
            index_time(position);
        }
    }

    // Moves every row out, in the order they were added, and leaves the table empty.
    [[nodiscard]] auto extract() -> std::vector<PersistentEvent>;
    auto clear() noexcept -> void;
    auto reserve(size_type capacity) -> void;

private:
    // Lets by_id_ be searched with a std::string_view without building a std::string.
    struct IdHash final
    {
        using is_transparent = void;
        [[nodiscard]] auto operator()(std::string_view id) const noexcept -> std::size_t
        {
            return std::hash<std::string_view>{}(id);
        }
    };

    // One row of the room-and-time index: its sort key and its position in rows_.
    struct TimeEntry final
    {
        std::int64_t origin_server_ts{0};
        std::uint64_t depth{0U};
        std::uint64_t stream_ordering{0U};
        std::size_t position{0U};
        [[nodiscard]] auto operator<=>(TimeEntry const&) const noexcept = default;
    };

    // The index entry `row`, at `position`, would have, or nullopt when it is not a timeline event.
    [[nodiscard]] static auto time_entry_for(PersistentEvent const& row, std::size_t position)
        -> std::optional<TimeEntry>;
    // Adds the row at `position` to the room-and-time index if it is a timeline event.
    auto index_time(std::size_t position) -> void;
    // Removes `entry` (what time_entry_for gave the row before it changed) from room `room_id`'s part.
    auto unindex_time(std::string_view room_id, std::optional<TimeEntry> const& entry) -> void;
    auto erase_marked(std::vector<bool> const& removed) -> std::size_t;

    std::vector<PersistentEvent> rows_{};
    // event_id -> position in rows_.
    std::unordered_map<std::string, std::size_t, IdHash, std::equal_to<>> by_id_{};
    // Positions in rows_, by ascending (stream_ordering, position).
    std::vector<std::size_t> stream_order_{};
    // room_id -> that room's timeline events by ascending TimeEntry.
    std::unordered_map<std::string, std::vector<TimeEntry>, IdHash, std::equal_to<>> by_room_time_{};
};

} // namespace merovingian::database
