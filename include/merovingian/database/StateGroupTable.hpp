// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/StateGroupKeyHash.hpp"
#include "merovingian/database/persistent_state_group.hpp"
#include "merovingian/database/state_group_table_support.hpp"

#include <cstddef>
#include <functional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace merovingian::database
{

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

} // namespace merovingian::database
