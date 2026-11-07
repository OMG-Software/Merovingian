// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <iterator>
#include <utility>
#include <vector>

namespace merovingian::database::detail
{

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

} // namespace merovingian::database::detail
