// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/database/LiveKitDelegationRowText.hpp"

#include "merovingian/database/LiveKitDelegationTable.hpp"

#include <cstdint>
#include <limits>
#include <string_view>

namespace merovingian::database
{
namespace
{

    // One or more ASCII digits whose value fits 64 bits; nullopt for anything else (empty, a sign, a space, a letter,
    // 21 digits).
    [[nodiscard]] auto strict_u64(std::string_view text) noexcept -> std::optional<std::uint64_t>
    {
        if (text.empty())
        {
            return std::nullopt;
        }
        auto value = std::uint64_t{0U};
        for (auto const character : text)
        {
            if (character < '0' || character > '9')
            {
                return std::nullopt;
            }
            auto const digit = static_cast<std::uint64_t>(character - '0');
            if (value > (std::numeric_limits<std::uint64_t>::max() - digit) / 10U)
            {
                return std::nullopt;
            }
            value = (value * 10U) + digit;
        }
        return value;
    }

} // namespace

auto parse_livekit_delegation_row(std::span<std::string const> columns) -> std::optional<PersistentLiveKitDelegation>
{
    if (columns.size() < livekit_delegation_row_columns)
    {
        return std::nullopt;
    }
    auto const created_ms = strict_u64(columns[5]);
    if (!created_ms.has_value())
    {
        return std::nullopt;
    }
    auto row = PersistentLiveKitDelegation{columns[0], columns[1], columns[2], columns[3], columns[4], *created_ms};
    if (!livekit_delegation_is_storable(row))
    {
        return std::nullopt;
    }
    return row;
}

} // namespace merovingian::database
