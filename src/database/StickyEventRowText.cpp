// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/database/StickyEventRowText.hpp"

#include "merovingian/database/StickyEventTable.hpp"

#include <limits>
#include <span>
#include <string>
#include <string_view>

namespace merovingian::database
{
namespace
{

    // One or more ASCII digits whose value fits a signed 64-bit integer; nullopt for anything else.
    [[nodiscard]] auto strict_i64(std::string_view text) noexcept -> std::optional<std::int64_t>
    {
        if (text.empty())
        {
            return std::nullopt;
        }
        auto value = std::int64_t{0};
        for (auto const character : text)
        {
            if (character < '0' || character > '9')
            {
                return std::nullopt;
            }
            auto const digit = static_cast<std::int64_t>(character - '0');
            if (value > (std::numeric_limits<std::int64_t>::max() - digit) / 10)
            {
                return std::nullopt;
            }
            value = (value * 10) + digit;
        }
        return value;
    }

} // namespace

auto parse_sticky_duration_ms(std::string_view text) noexcept -> std::optional<std::int64_t>
{
    auto const value = strict_i64(text);
    if (!value.has_value() || *value < 1)
    {
        return std::nullopt;
    }
    return value;
}

auto parse_sticky_event_row(std::span<std::string const> columns) -> std::optional<PersistentStickyEvent>
{
    if (columns.size() < sticky_event_row_columns)
    {
        return std::nullopt;
    }
    auto const received_at_ms = strict_i64(columns[3]);
    auto const expires_at_ms = strict_i64(columns[4]);
    if (!received_at_ms.has_value() || !expires_at_ms.has_value())
    {
        return std::nullopt;
    }
    auto row = PersistentStickyEvent{columns[0], columns[1], columns[2], *received_at_ms, *expires_at_ms};
    if (!sticky_event_is_storable(row))
    {
        return std::nullopt;
    }
    return row;
}

} // namespace merovingian::database
