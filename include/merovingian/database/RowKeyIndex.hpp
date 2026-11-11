// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>

namespace merovingian::database
{

// The position in a row vector of each row, by a string key that is unique across the rows (ADR-0603). It is the
// shape of `state_position_index` (ADR-0344): it sits beside a vector the store owns and is trusted only while it
// was built for exactly the vector's current row count, so a caller that edits the vector directly (a test) leaves
// the counts unequal and the reader scans until the next rebuild. The index holds no pointers and no row data.
//
// Not thread-safe: the store's owner serialises access (the runtime lock).
class RowKeyIndex final
{
public:
    // True while the index describes a vector of `row_count` rows.
    [[nodiscard]] auto in_step(std::size_t row_count) const noexcept -> bool
    {
        return indexed_rows_ == row_count;
    }

    auto clear() -> void
    {
        positions_.clear();
        indexed_rows_ = 0U;
    }

    // Rebuilds from `rows`; `key_of(row)` is a row's key. The first of two rows with one key wins, as a scan would.
    template <typename Rows, typename KeyOf>
    auto rebuild(Rows const& rows, KeyOf key_of) -> void
    {
        positions_.clear();
        positions_.reserve(rows.size());
        auto position = std::size_t{0U};
        for (auto const& row : rows)
        {
            positions_.emplace(key_of(row), position);
            ++position;
        }
        indexed_rows_ = rows.size();
    }

    // Records the row just appended, now the `row_count`th. Does nothing unless the index was in step before it,
    // so an index that was out of step stays out of step until the next rebuild.
    auto note_appended(std::size_t row_count, std::string key) -> void
    {
        if (row_count == 0U || indexed_rows_ + 1U != row_count)
        {
            return;
        }
        positions_.emplace(std::move(key), row_count - 1U);
        indexed_rows_ = row_count;
    }

    // The position the key names, or nullopt. Meaningful only while in step; the caller checks that the row it
    // finds carries the key.
    [[nodiscard]] auto find(std::string const& key) const -> std::optional<std::size_t>
    {
        auto const found = positions_.find(key);
        return found == positions_.end() ? std::nullopt : std::optional<std::size_t>{found->second};
    }

    // The vector erased `erased_key`'s row at `position` by moving its last row into the gap and shrinking by one.
    // `moved_key` is the key of the row that was last (unused when the erased row was the last). `old_row_count`
    // is the vector's size before the erase. Does nothing unless the index was in step before it.
    auto erase_swap(std::size_t position, std::string const& erased_key, std::string const& moved_key,
                    std::size_t old_row_count) -> void
    {
        if (indexed_rows_ != old_row_count || position >= old_row_count)
        {
            return;
        }
        positions_.erase(erased_key);
        if (position + 1U != old_row_count)
        {
            positions_[moved_key] = position;
        }
        indexed_rows_ = old_row_count - 1U;
    }

private:
    std::unordered_map<std::string, std::size_t> positions_{};
    std::size_t indexed_rows_{0U};
};

} // namespace merovingian::database
