// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/PersistentEventStateGroup.hpp"
#include "merovingian/database/StateGroupKeyHash.hpp"
#include "merovingian/database/StateGroupTableSupport.hpp"

#include <cstddef>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace merovingian::database
{

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
