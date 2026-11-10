// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/sync/ToDevicePosition.hpp"

#include <limits>

namespace merovingian::sync
{

namespace
{

    // A decimal number with no sign, no leading zero (other than "0" itself) and no value past 2^64-1. The
    // old reader stopped at the first non-digit, so "12abc" acknowledged everything up to 12.
    [[nodiscard]] auto decode_decimal(std::string_view text) -> std::optional<std::uint64_t>
    {
        if (text.empty() || (text.size() > 1U && text.front() == '0'))
        {
            return std::nullopt;
        }
        constexpr auto max = std::numeric_limits<std::uint64_t>::max();
        auto value = std::uint64_t{0U};
        for (auto const ch : text)
        {
            if (ch < '0' || ch > '9')
            {
                return std::nullopt;
            }
            auto const digit = static_cast<std::uint64_t>(ch - '0');
            if (value > (max - digit) / 10U)
            {
                return std::nullopt;
            }
            value = (value * 10U) + digit;
        }
        return value;
    }

} // namespace

auto encode_to_device_position(ToDevicePosition position) -> std::string
{
    auto encoded = std::to_string(position.stream_id);
    if (position.epoch != 0U)
    {
        encoded += "_" + std::to_string(position.epoch);
    }
    return encoded;
}

auto decode_to_device_position(std::string_view encoded) -> std::optional<ToDevicePosition>
{
    auto const separator = encoded.find('_');
    auto const stream_id = decode_decimal(encoded.substr(0U, separator));
    if (!stream_id.has_value())
    {
        return std::nullopt;
    }
    if (separator == std::string_view::npos)
    {
        return ToDevicePosition{*stream_id, 0U};
    }
    // Zero is written by leaving the epoch out, so "_0" is not a spelling of it; a second '_' fails the digits.
    auto const epoch = decode_decimal(encoded.substr(separator + 1U));
    if (!epoch.has_value() || *epoch == 0U)
    {
        return std::nullopt;
    }
    return ToDevicePosition{*stream_id, *epoch};
}

} // namespace merovingian::sync
