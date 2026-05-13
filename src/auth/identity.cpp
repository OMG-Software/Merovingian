// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/auth/identity.hpp"

#include <algorithm>
#include <cstdint>

namespace merovingian::auth
{
namespace
{

[[nodiscard]] auto is_ascii_digit(char value) noexcept -> bool
{
    return value >= '0' && value <= '9';
}

[[nodiscard]] auto is_ascii_lower(char value) noexcept -> bool
{
    return value >= 'a' && value <= 'z';
}

[[nodiscard]] auto is_ascii_upper(char value) noexcept -> bool
{
    return value >= 'A' && value <= 'Z';
}

[[nodiscard]] auto is_ascii_alnum(char value) noexcept -> bool
{
    return is_ascii_lower(value) || is_ascii_upper(value) || is_ascii_digit(value);
}

[[nodiscard]] auto is_printable_ascii_without_space(char value) noexcept -> bool
{
    auto const byte = static_cast<unsigned char>(value);
    return byte > 0x20U && byte < 0x7FU;
}

[[nodiscard]] auto is_localpart_character(char value) noexcept -> bool
{
    return is_ascii_lower(value) || is_ascii_digit(value) || value == '.' || value == '_' || value == '-'
        || value == '=' || value == '/' || value == '+';
}

[[nodiscard]] auto port_is_valid(std::string_view port) noexcept -> bool
{
    if (port.empty() || port.size() > 5U || !std::ranges::all_of(port, is_ascii_digit))
    {
        return false;
    }

    auto parsed_port = std::uint32_t{0};
    for (auto const digit : port)
    {
        parsed_port = (parsed_port * 10U) + static_cast<std::uint32_t>(digit - '0');
    }

    return parsed_port <= 65535U;
}

[[nodiscard]] auto hostname_is_valid(std::string_view hostname) noexcept -> bool
{
    if (hostname.empty() || hostname.front() == '.' || hostname.back() == '.')
    {
        return false;
    }

    auto label_start = std::size_t{0};
    while (label_start < hostname.size())
    {
        auto const label_end = hostname.find('.', label_start);
        auto const end = label_end == std::string_view::npos ? hostname.size() : label_end;
        auto const label = hostname.substr(label_start, end - label_start);
        if (label.empty() || label.size() > 63U || label.front() == '-' || label.back() == '-')
        {
            return false;
        }
        if (!std::ranges::all_of(label, [](char const value) { return is_ascii_alnum(value) || value == '-'; }))
        {
            return false;
        }

        if (label_end == std::string_view::npos)
        {
            break;
        }
        label_start = label_end + 1U;
    }

    return true;
}

[[nodiscard]] auto bracketed_ipv6_literal_is_valid(std::string_view literal) noexcept -> bool
{
    if (literal.size() < 4U || literal.front() != '[')
    {
        return false;
    }

    auto const close = literal.find(']');
    if (close == std::string_view::npos || close == 1U)
    {
        return false;
    }

    auto const address = literal.substr(1U, close - 1U);
    auto const suffix = literal.substr(close + 1U);
    if (address.find(':') == std::string_view::npos)
    {
        return false;
    }
    if (!std::ranges::all_of(address, [](char const value) {
            return is_ascii_digit(value) || (value >= 'a' && value <= 'f') || (value >= 'A' && value <= 'F')
                || value == ':' || value == '.';
        }))
    {
        return false;
    }
    if (suffix.empty())
    {
        return true;
    }

    return suffix.front() == ':' && port_is_valid(suffix.substr(1U));
}

} // namespace

auto server_name_is_valid(std::string_view server_name) noexcept -> bool
{
    if (server_name.empty() || server_name.size() > 255U)
    {
        return false;
    }

    if (server_name.front() == '[')
    {
        return bracketed_ipv6_literal_is_valid(server_name);
    }

    auto const colon = server_name.find(':');
    if (colon == std::string_view::npos)
    {
        return hostname_is_valid(server_name);
    }
    if (server_name.find(':', colon + 1U) != std::string_view::npos)
    {
        return false;
    }

    auto const hostname = server_name.substr(0U, colon);
    auto const port = server_name.substr(colon + 1U);
    return hostname_is_valid(hostname) && port_is_valid(port);
}

auto user_id_is_valid(std::string_view user_id) noexcept -> bool
{
    if (user_id.size() < 4U || user_id.size() > 255U || user_id.front() != '@')
    {
        return false;
    }

    auto const separator = user_id.find(':');
    if (separator == std::string_view::npos || separator <= 1U || separator + 1U >= user_id.size())
    {
        return false;
    }

    auto const localpart = user_id.substr(1U, separator - 1U);
    auto const server_name = user_id.substr(separator + 1U);
    return std::ranges::all_of(localpart, is_localpart_character) && server_name_is_valid(server_name);
}

auto device_id_is_valid(std::string_view device_id) noexcept -> bool
{
    return !device_id.empty() && device_id.size() <= 255U
        && std::ranges::all_of(device_id, is_printable_ascii_without_space);
}

auto password_is_acceptable(std::string_view password) noexcept -> bool
{
    auto has_lower = false;
    auto has_upper = false;
    auto has_digit = false;
    auto has_symbol = false;

    for (auto const value : password)
    {
        auto const byte = static_cast<unsigned char>(value);
        has_lower = has_lower || is_ascii_lower(value);
        has_upper = has_upper || is_ascii_upper(value);
        has_digit = has_digit || is_ascii_digit(value);
        has_symbol = has_symbol || (byte >= 0x21U && byte <= 0x7EU && !is_ascii_alnum(value));
    }

    return password.size() >= 12U && has_lower && has_upper && has_digit && has_symbol;
}

auto login_policy(UserIdentity const& user) -> LoginPolicyDecision
{
    if (!user_id_is_valid(user.user_id))
    {
        return {false, "invalid user_id"};
    }
    if (!user.password_login_enabled)
    {
        return {false, "password login disabled"};
    }
    if (user.state == AccountState::locked)
    {
        return {false, "account locked"};
    }
    if (user.state == AccountState::suspended)
    {
        return {false, "account suspended"};
    }

    return {true, {}};
}

} // namespace merovingian::auth
