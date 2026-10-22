// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/persistent_event.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <ranges>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace merovingian::database
{

// The in-memory mirror of the `events` table (ADR-0215). It owns the rows and keeps two indexes
// over them, so every writer keeps them consistent by construction:
//
//   - by event ID: find() is a hash lookup, not a scan of every stored event;
//   - by stream order: in_stream_order() visits rows by ascending stream_ordering (rows with equal
//     stream_ordering in the order they were added), whatever order they arrived in.
//
// Iterating the table itself visits rows in the order they were added, which is NOT stream order:
// hydration selects with no ORDER BY, PostgreSQL moves a row whose status is updated, and stream
// orderings commit out of order across rooms. Both indexes hold positions in the row vector, never
// iterators or pointers, so they survive its reallocation.
//
// Rows are read-only through the table except through modify(), which cannot change the two
// indexed fields. An event ID is held at most once, as it is the table's primary key on disk.
// The table has no lock of its own: it is guarded by whatever guards the PersistentStore that owns
// it (`runtime.mutex` in the homeserver).
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
        auto& target = rows_[static_cast<std::size_t>(row - rows_.cbegin())];
        auto event_id = target.event_id;
        auto const stream_ordering = target.stream_ordering;
        std::invoke(mutation, target);
        target.event_id = std::move(event_id);
        target.stream_ordering = stream_ordering;
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

    auto erase_marked(std::vector<bool> const& removed) -> std::size_t;

    std::vector<PersistentEvent> rows_{};
    // event_id -> position in rows_.
    std::unordered_map<std::string, std::size_t, IdHash, std::equal_to<>> by_id_{};
    // Positions in rows_, by ascending (stream_ordering, position).
    std::vector<std::size_t> stream_order_{};
};

} // namespace merovingian::database
