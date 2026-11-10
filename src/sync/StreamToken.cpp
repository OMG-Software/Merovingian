// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/sync/StreamToken.hpp"

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
        // 16 hex digits fill a uint64_t exactly; anything longer would wrap
        // the shift-accumulate below, letting a crafted token decode to a
        // truncated (arbitrarily small) ordering (#456).
        constexpr auto max_hex_digits = std::size_t{16U};
        if (encoded.empty() || encoded.size() > max_hex_digits)
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
    auto encoded = encode_component(token.event_ordering) + "_" + encode_component(token.membership_ordering) + "_" +
                   encode_component(token.sync_stream_id);
    if (token.epoch != 0U)
    {
        encoded += "_" + encode_component(token.epoch);
    }
    return encoded;
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
    auto const tail =
        second_separator == std::string_view::npos ? std::string_view{} : remainder.substr(second_separator + 1U);
    auto const third_separator = tail.find('_');
    auto const sync_part = tail.substr(0U, third_separator);
    auto const epoch_part = third_separator == std::string_view::npos ? std::optional<std::string_view>{}
                                                                      : tail.substr(third_separator + 1U);
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
    // ADR-0592: an epoch component follows a sync component, holds one hex number and is never zero, which is
    // written by leaving the component out; so every token has one spelling and nothing follows the epoch.
    auto epoch = std::uint64_t{0U};
    if (epoch_part.has_value())
    {
        auto const decoded = sync_part.empty() ? std::nullopt : decode_component(*epoch_part);
        if (!decoded.has_value() || *decoded == 0U)
        {
            return std::nullopt;
        }
        epoch = *decoded;
    }
    return StreamToken{*event_ordering, *membership_ordering, sync_stream_id, epoch};
}

auto is_valid_stream_token(std::string_view encoded) noexcept -> bool
{
    return decode_stream_token(encoded).has_value();
}

} // namespace merovingian::sync