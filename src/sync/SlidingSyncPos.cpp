// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/sync/SlidingSyncPos.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>

namespace merovingian::sync
{

namespace
{

    constexpr auto page_separator = '.';
    constexpr auto max_page_digits = std::size_t{20U};
    // A bound pos ends in `-` and the MAC's 64 lowercase hex digits (ADR-0866).
    constexpr auto binding_separator = '-';
    constexpr auto binding_hex_digits = std::size_t{64U};

    [[nodiscard]] auto is_binding(std::string_view text) noexcept -> bool
    {
        return text.size() == binding_hex_digits && std::ranges::all_of(text, [](char const ch) {
                   return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
               });
    }

    // 1 to 20 ASCII digits with no leading zero that fit 64 bits; 0 is never written, so it is refused too.
    [[nodiscard]] auto decode_page(std::string_view digits) -> std::optional<std::uint64_t>
    {
        if (digits.empty() || digits.size() > max_page_digits || digits.front() == '0')
        {
            return std::nullopt;
        }
        auto value = std::uint64_t{0U};
        for (auto const ch : digits)
        {
            if (ch < '0' || ch > '9')
            {
                return std::nullopt;
            }
            auto const digit = static_cast<std::uint64_t>(ch - '0');
            if (value > (std::numeric_limits<std::uint64_t>::max() - digit) / 10U)
            {
                return std::nullopt;
            }
            value = value * 10U + digit;
        }
        return value;
    }

} // namespace

auto encode_sliding_sync_pos(SlidingSyncPos const& pos) -> std::string
{
    auto text = encode_stream_token(pos.token);
    if (pos.page != 0U)
    {
        text.push_back(page_separator);
        text += std::to_string(pos.page);
    }
    return text;
}

auto decode_sliding_sync_pos(std::string_view encoded) -> std::optional<SlidingSyncPos>
{
    auto const separator = encoded.find(page_separator);
    auto const token = decode_stream_token(encoded.substr(0U, separator));
    if (!token.has_value())
    {
        return std::nullopt;
    }
    if (separator == std::string_view::npos)
    {
        return SlidingSyncPos{*token, 0U};
    }
    auto const page = decode_page(encoded.substr(separator + 1U));
    if (!page.has_value())
    {
        return std::nullopt;
    }
    return SlidingSyncPos{*token, *page};
}

auto decode_sync_position_token(std::string_view text) -> std::optional<StreamToken>
{
    if (auto const token = decode_stream_token(text); token.has_value())
    {
        return token;
    }
    auto const separator = text.rfind(binding_separator);
    if (separator == std::string_view::npos || !is_binding(text.substr(separator + 1U)))
    {
        return std::nullopt;
    }
    auto const pos = decode_sliding_sync_pos(text.substr(0U, separator));
    return pos.has_value() ? std::optional<StreamToken>{pos->token} : std::nullopt;
}

} // namespace merovingian::sync
