// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/oauth/AuthorizationRedirect.hpp"

#include <array>
#include <cstddef>
#include <string>
#include <string_view>

namespace merovingian::oauth
{

namespace
{

    // RFC 3986 section 2.3.
    [[nodiscard]] constexpr auto is_unreserved(char value) noexcept -> bool
    {
        return (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z') || (value >= '0' && value <= '9') ||
               value == '-' || value == '.' || value == '_' || value == '~';
    }

    constexpr auto hex_digits =
        std::array<char, 16U>{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

} // namespace

auto percent_encode_redirect_value(std::string_view value) -> std::string
{
    auto encoded = std::string{};
    encoded.reserve(value.size());
    for (auto const character : value)
    {
        if (is_unreserved(character))
        {
            encoded.push_back(character);
            continue;
        }
        auto const byte = static_cast<unsigned char>(character);
        encoded.push_back('%');
        encoded.push_back(hex_digits[static_cast<std::size_t>(byte >> 4U)]);
        encoded.push_back(hex_digits[static_cast<std::size_t>(byte & 0x0FU)]);
    }
    return encoded;
}

auto authorization_redirect_address(ParsedUri const& target, ResponseMode mode,
                                    std::span<RedirectParameter const> parameters) -> std::string
{
    auto address = target.text();
    if (parameters.empty())
    {
        return address;
    }
    if (mode == ResponseMode::fragment)
    {
        address.push_back('#');
    }
    else if (!target.has_query())
    {
        address.push_back('?');
    }
    else if (!target.query().empty())
    {
        address.push_back('&');
    }
    auto first = true;
    for (auto const& [name, value] : parameters)
    {
        if (!first)
        {
            address.push_back('&');
        }
        first = false;
        address.append(percent_encode_redirect_value(name));
        address.push_back('=');
        address.append(percent_encode_redirect_value(value));
    }
    return address;
}

} // namespace merovingian::oauth
