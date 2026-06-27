// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/sync/stream_token.hpp"

#include <algorithm>
#include <cmath>
#include <limits>

namespace merovingian::sync
{

namespace
{

    [[nodiscard]] auto encode_component(std::uint64_t value) -> std::string
    {
        static constexpr char const* digits = "0123456789abcdef";
        if (value == 0U)
        {
            return "0";
        }
        auto result = std::string{};
        auto remaining = value;
        while (remaining > 0U)
        {
            result.push_back(digits[remaining & 0xFU]);
            remaining >>= 4U;
        }
        std::reverse(result.begin(), result.end());
        return result;
    }

    [[nodiscard]] auto decode_component(std::string_view encoded) -> std::optional<std::uint64_t>
    {
        if (encoded.empty())
        {
            return std::nullopt;
        }
        auto result = std::uint64_t{0U};
        for (auto const ch : encoded)
        {
            result <<= 4U;
            if (ch >= '0' && ch <= '9')
            {
                result += static_cast<std::uint64_t>(ch - '0');
            }
            else if (ch >= 'a' && ch <= 'f')
            {
                result += static_cast<std::uint64_t>(ch - 'a') + 10U;
            }
            else if (ch >= 'A' && ch <= 'F')
            {
                result += static_cast<std::uint64_t>(ch - 'A') + 10U;
            }
            else
            {
                return std::nullopt;
            }
        }
        return result;
    }

} // namespace

auto encode_stream_token(StreamToken token) -> std::string
{
    return encode_component(token.event_ordering) + "_" + encode_component(token.membership_ordering) + "_" +
           encode_component(token.sync_stream_id);
}

auto decode_stream_token(std::string_view encoded) -> std::optional<StreamToken>
{
    auto const first_separator = encoded.find('_');
    if (first_separator == std::string_view::npos)
    {
        return std::nullopt;
    }
    auto const event_part = encoded.substr(0U, first_separator);
    auto const remainder = encoded.substr(first_separator + 1U);
    auto const second_separator = remainder.find('_');
    auto const membership_part = remainder.substr(0U, second_separator);
    auto const sync_part =
        second_separator == std::string_view::npos ? std::string_view{} : remainder.substr(second_separator + 1U);
    if (event_part.empty() || membership_part.empty())
    {
        return std::nullopt;
    }
    auto const event_ordering = decode_component(event_part);
    auto const membership_ordering = decode_component(membership_part);
    if (!event_ordering.has_value() || !membership_ordering.has_value())
    {
        return std::nullopt;
    }
    auto sync_stream_id = std::uint64_t{0U};
    if (!sync_part.empty())
    {
        auto const decoded = decode_component(sync_part);
        if (!decoded.has_value())
        {
            return std::nullopt;
        }
        sync_stream_id = *decoded;
    }
    return StreamToken{*event_ordering, *membership_ordering, sync_stream_id};
}

auto is_valid_stream_token(std::string_view encoded) noexcept -> bool
{
    return decode_stream_token(encoded).has_value();
}

} // namespace merovingian::sync