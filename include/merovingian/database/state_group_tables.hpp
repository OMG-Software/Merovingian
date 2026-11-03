// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/persistent_state_group.hpp"

#include <cstddef>
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

// The in-memory mirrors of the three state-group tables (ADR-0064, ADR-0325): `state_groups`,
// `state_group_state` and `event_state_groups`. Each owns its rows and keeps a hash index over them,
// so a lookup by key costs the key's rows, never a pass over every room's rows on the server. This
// is the pattern `EventTable` set (ADR-0215, ADR-0300):
//
//   - the rows are exposed read-only (iteration, size, operator[]), so a reader that walks the whole
//     table still compiles;
//   - every change goes through the table's own insert / erase_if / clear, so a writer cannot
//     bypass the index (a direct `push_back` or `erase` does not compile);
//   - the indexes hold positions in the row vector, never iterators or pointers, so they survive its
//     reallocation.
//
// Iterating a table visits rows in the order they were added. Nothing is persisted here: hydration
// and reload_room fill the tables and the indexes come with the rows.
//
// THREAD SAFETY. A table has no lock; it is guarded by whatever guards the PersistentStore that owns
// it (`runtime.mutex` in the homeserver). A write reallocates the row vector and may rehash the
// index, and the three tables are changed one after another (reload_room), so a reader needs the
// same exclusion from writers that it needed for the `std::vector`s these replaced. The views and
// `std::string_view` results below point into the rows and are valid only until the next write.

namespace detail
{
    // Lets an index be searched with a std::string_view without building a std::string.
    struct StateGroupKeyHash final
    {
        using is_transparent = void;
        [[nodiscard]] auto operator()(std::string_view key) const noexcept -> std::size_t
        {
            return std::hash<std::string_view>{}(key);
        }
    };

    // Old position -> position after the rows `removed` marks are taken out; `removed_position` for a
    // removed row. Compacts `rows` in place.
    inline constexpr auto removed_position = static_cast<std::size_t>(-1);
    template <typename Row>
    [[nodiscard]] auto compact_unmarked(std::vector<Row>& rows, std::vector<bool> const& removed)
        -> std::vector<std::size_t>
    {
        auto remap = std::vector<std::size_t>(rows.size(), removed_position);
        auto kept = std::size_t{0U};
        for (auto position = std::size_t{0U}; position < rows.size(); ++position)
        {
            if (removed[position])
            {
                continue;
            }
            remap[position] = kept;
            if (kept != position)
            {
                rows[kept] = std::move(rows[position]);
            }
            ++kept;
        }
        rows.erase(rows.begin() + static_cast<std::ptrdiff_t>(kept), rows.end());
        return remap;
    }
} // namespace detail

// `state_groups`: one row per state group, found by `state_group_id`. A group ID is held at most once
// (it is the table's primary key on disk); inserting a second row with a held ID keeps the first.
class StateGroupTable final
{
public:
    using value_type = PersistentStateGroup;
    using size_type = std::size_t;
    using const_iterator = std::vector<PersistentStateGroup>::const_iterator;
    using iterator = const_iterator;

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
    [[nodiscard]] auto operator[](size_type position) const -> PersistentStateGroup const&
    {
        return rows_[position];
    }
    [[nodiscard]] auto rows() const noexcept -> std::vector<PersistentStateGroup> const&
    {
        return rows_;
    }

    // The group whose ID is `state_group_id`, or end(). A hash lookup.
    [[nodiscard]] auto find(std::string_view state_group_id) const -> const_iterator;
    [[nodiscard]] auto contains(std::string_view state_group_id) const -> bool;

    // Adds `group` unless a row with its ID is held; returns whether it was added.
    [[nodiscard]] auto insert(PersistentStateGroup group) -> bool;
    // insert() for each of `groups`: the hydration and room-reload path. Returns how many were added.
    auto insert_all(std::vector<PersistentStateGroup> groups) -> std::size_t;
    // Removes every row `predicate` accepts and repairs the index in one linear pass, without
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
    auto clear() noexcept -> void;

private:
    auto erase_marked(std::vector<bool> const& removed) -> std::size_t;

    std::vector<PersistentStateGroup> rows_{};
    // state_group_id -> position in rows_.
    std::unordered_map<std::string, std::size_t, detail::StateGroupKeyHash, std::equal_to<>> by_id_{};
};

// `state_group_state`: a group's own entries (the full state of a snapshot, the changed entries of a
// delta), found by `state_group_id`. entries_of() visits a group's entries in the order they were
// added, which is the order the flat table held them in.
class StateGroupEntryTable final
{
public:
    using value_type = PersistentStateGroupStateEntry;
    using size_type = std::size_t;
    using const_iterator = std::vector<PersistentStateGroupStateEntry>::const_iterator;
    using iterator = const_iterator;

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
    [[nodiscard]] auto operator[](size_type position) const -> PersistentStateGroupStateEntry const&
    {
        return rows_[position];
    }
    [[nodiscard]] auto rows() const noexcept -> std::vector<PersistentStateGroupStateEntry> const&
    {
        return rows_;
    }

    // The entries whose `state_group_id` is `state_group_id`, in the order they were added; empty for
    // a group with none. Costs nothing per row of any other group. Valid until the table is next
    // changed.
    [[nodiscard]] auto entries_of(std::string_view state_group_id) const
    {
        auto const found = by_group_.find(state_group_id);
        auto const& positions = found == by_group_.end() ? no_positions_ : found->second;
        return std::views::transform(positions, [this](std::size_t position) -> PersistentStateGroupStateEntry const& {
            return rows_[position];
        });
    }
    // How many entries `state_group_id` holds.
    [[nodiscard]] auto count_of(std::string_view state_group_id) const -> std::size_t;

    // Adds `entry` (a group may hold several entries, one per (event_type, state_key)).
    auto insert(PersistentStateGroupStateEntry entry) -> void;
    // insert() for each of `entries`: the hydration and room-reload path.
    auto insert_all(std::vector<PersistentStateGroupStateEntry> entries) -> void;
    // Removes every row `predicate` accepts and repairs the index in one linear pass, without
    // rehashing the remaining group IDs. Returns how many were removed.
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
    auto clear() noexcept -> void;

private:
    auto erase_marked(std::vector<bool> const& removed) -> std::size_t;

    static inline std::vector<std::size_t> const no_positions_{};

    std::vector<PersistentStateGroupStateEntry> rows_{};
    // state_group_id -> positions in rows_, ascending.
    std::unordered_map<std::string, std::vector<std::size_t>, detail::StateGroupKeyHash, std::equal_to<>> by_group_{};
};

// `event_state_groups`: the state group holding the room's state after each event, found by
// `event_id`. An event ID is held at most once (the table's primary key on disk); assigning a held
// event another group replaces its row.
class EventStateGroupTable final
{
public:
    using value_type = PersistentEventStateGroup;
    using size_type = std::size_t;
    using const_iterator = std::vector<PersistentEventStateGroup>::const_iterator;
    using iterator = const_iterator;

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
    [[nodiscard]] auto operator[](size_type position) const -> PersistentEventStateGroup const&
    {
        return rows_[position];
    }
    [[nodiscard]] auto rows() const noexcept -> std::vector<PersistentEventStateGroup> const&
    {
        return rows_;
    }

    // The ID of the state group recorded for `event_id`, or nullopt. A hash lookup. The view points
    // into the row: valid until the table is next changed.
    [[nodiscard]] auto state_group_of(std::string_view event_id) const -> std::optional<std::string_view>;
    [[nodiscard]] auto contains(std::string_view event_id) const -> bool;

    // Records `state_group_id` for `event_id`, replacing the group a held row names.
    auto assign(std::string_view event_id, std::string_view state_group_id) -> void;
    // assign() for each of `mappings`: the hydration and room-reload path.
    auto insert_all(std::vector<PersistentEventStateGroup> mappings) -> void;
    // Removes every row `predicate` accepts and repairs the index in one linear pass, without
    // rehashing the remaining event IDs. Returns how many were removed.
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
    auto clear() noexcept -> void;

private:
    auto erase_marked(std::vector<bool> const& removed) -> std::size_t;

    std::vector<PersistentEventStateGroup> rows_{};
    // event_id -> position in rows_.
    std::unordered_map<std::string, std::size_t, detail::StateGroupKeyHash, std::equal_to<>> by_event_{};
};

} // namespace merovingian::database
