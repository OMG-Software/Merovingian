// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/PersistentStateGroupStateEntry.hpp"
#include "merovingian/database/StateGroupKeyHash.hpp"
#include "merovingian/database/StateGroupTableSupport.hpp"

#include <cstddef>
#include <functional>
#include <ranges>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace merovingian::database
{

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

} // namespace merovingian::database
