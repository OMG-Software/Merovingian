// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/database/DelayedEventRowText.hpp"

#include "merovingian/database/DelayedEventStatus.hpp"
#include "merovingian/database/DelayedEventStatusText.hpp"
#include "merovingian/database/DelayedEventStore.hpp"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <string>
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

    // The two texts the store writes for a boolean.
    [[nodiscard]] auto strict_bool(std::string_view text) noexcept -> std::optional<bool>
    {
        if (text == "true")
        {
            return true;
        }
        if (text == "false")
        {
            return false;
        }
        return std::nullopt;
    }

} // namespace

auto parse_delayed_event_row(std::span<std::string const> columns) -> std::optional<PersistentDelayedEvent>
{
    if (columns.size() < delayed_event_row_columns)
    {
        return std::nullopt;
    }
    auto const status = parse_delayed_event_status(columns[12]);
    auto const is_state = strict_bool(columns[5]);
    auto const via_appservice = strict_bool(columns[9]);
    auto const delay_ms = strict_u64(columns[10]);
    auto const delayed_since_ms = strict_u64(columns[11]);
    auto const finalised_at_ms = strict_u64(columns[13]);
    if (!status.has_value() || !is_state.has_value() || !via_appservice.has_value() || !delay_ms.has_value() ||
        !delayed_since_ms.has_value() || !finalised_at_ms.has_value())
    {
        return std::nullopt;
    }
    if (*status == DelayedEventStatus::scheduled)
    {
        if (*delay_ms < 1U || *delay_ms > max_delayed_event_delay_ms)
        {
            return std::nullopt;
        }
    }
    else if (*finalised_at_ms == 0U)
    {
        return std::nullopt;
    }
    return PersistentDelayedEvent{columns[0], columns[1],       columns[2],  columns[3],
                                  columns[4], *is_state,        columns[6],  columns[7],
                                  columns[8], *via_appservice,  *delay_ms,   *delayed_since_ms,
                                  *status,    *finalised_at_ms, columns[14], columns[15]};
}

} // namespace merovingian::database
