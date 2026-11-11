// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <limits>
#include <string>
#include <unordered_map>
#include <vector>

namespace merovingian::database
{

// The positions in a row vector of the rows that share a string key (a user's devices, a device's one-time keys,
// a backup's sessions), kept as one linked list per key in insertion order (ADR-0603). It sits beside a vector the
// store owns, with the trust rule of `state_room_index` (ADR-0344): it is used only while it was built for exactly
// the vector's current row count, and a reader that finds it out of step scans the vector instead.
//
// A list, not a vector of positions per key, so that erasing one row by moving the last row into its place
// (`erase_swap`) costs the same however many rows share the key: a user with half a million backup sessions
// deletes one of them without touching the other 499999. Rows are visited in insertion order.
//
// Not thread-safe: the store's owner serialises access (the runtime lock).
class RowGroupIndex final
{
public:
    [[nodiscard]] auto in_step(std::size_t row_count) const noexcept -> bool
    {
        return next_.size() == row_count;
    }

    auto clear() -> void
    {
        groups_.clear();
        next_.clear();
        previous_.clear();
    }

    // Rebuilds from `rows`; `group_of(row)` is a row's key.
    template <typename Rows, typename GroupOf>
    auto rebuild(Rows const& rows, GroupOf group_of) -> void
    {
        clear();
        next_.reserve(rows.size());
        previous_.reserve(rows.size());
        auto position = std::size_t{0U};
        for (auto const& row : rows)
        {
            append(position, group_of(row));
            ++position;
        }
    }

    // Records the row just appended, now the `row_count`th. Does nothing unless the index was in step before it.
    auto note_appended(std::size_t row_count, std::string const& group) -> void
    {
        if (row_count == 0U || next_.size() + 1U != row_count)
        {
            return;
        }
        append(row_count - 1U, group);
    }

    // The number of rows under `group`. Meaningful only while in step.
    [[nodiscard]] auto count(std::string const& group) const -> std::size_t
    {
        auto const found = groups_.find(group);
        return found == groups_.end() ? 0U : found->second.count;
    }

    // Calls `visit(position)` for each row under `group`, in insertion order, until it returns false. `visit` must
    // not change the index. Meaningful only while in step.
    template <typename Visit>
    auto for_each(std::string const& group, Visit visit) const -> void
    {
        auto const found = groups_.find(group);
        if (found == groups_.end())
        {
            return;
        }
        for (auto position = found->second.head; position != none;)
        {
            auto const following = next_[position];
            if (!visit(position))
            {
                return;
            }
            position = following;
        }
    }

    // The vector erased the row at `position` (key `erased_group`) by moving its last row (key `last_group`) into
    // the gap and shrinking by one. `old_row_count` is the vector's size before the erase. Does nothing unless the
    // index was in step before it.
    auto erase_swap(std::size_t position, std::string const& erased_group, std::string const& last_group,
                    std::size_t old_row_count) -> void
    {
        if (next_.size() != old_row_count || position >= old_row_count)
        {
            return;
        }
        unlink(position, erased_group);
        auto const last = old_row_count - 1U;
        if (position != last)
        {
            auto& group = groups_[last_group];
            auto const before = previous_[last];
            auto const after = next_[last];
            previous_[position] = before;
            next_[position] = after;
            if (before == none)
            {
                group.head = position;
            }
            else
            {
                next_[before] = position;
            }
            if (after == none)
            {
                group.tail = position;
            }
            else
            {
                previous_[after] = position;
            }
        }
        next_.pop_back();
        previous_.pop_back();
    }

private:
    static constexpr auto none = std::numeric_limits<std::size_t>::max();

    struct Group final
    {
        std::size_t head{none};
        std::size_t tail{none};
        std::size_t count{0U};
    };

    auto append(std::size_t position, std::string const& group_key) -> void
    {
        auto& group = groups_[group_key];
        next_.push_back(none);
        previous_.push_back(group.tail);
        if (group.tail == none)
        {
            group.head = position;
        }
        else
        {
            next_[group.tail] = position;
        }
        group.tail = position;
        ++group.count;
    }

    auto unlink(std::size_t position, std::string const& group_key) -> void
    {
        auto const found = groups_.find(group_key);
        if (found == groups_.end())
        {
            return;
        }
        auto& group = found->second;
        auto const before = previous_[position];
        auto const after = next_[position];
        if (before == none)
        {
            group.head = after;
        }
        else
        {
            next_[before] = after;
        }
        if (after == none)
        {
            group.tail = before;
        }
        else
        {
            previous_[after] = before;
        }
        if (--group.count == 0U)
        {
            groups_.erase(found);
        }
    }

    std::unordered_map<std::string, Group> groups_{};
    std::vector<std::size_t> next_{};
    std::vector<std::size_t> previous_{};
};

} // namespace merovingian::database
