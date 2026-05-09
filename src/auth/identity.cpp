// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/auth/identity.hpp>

#include <algorithm>
#include <cctype>

namespace merovingian::auth
{
namespace
{

[[nodiscard]] auto is_printable_ascii_without_space(char value) noexcept -> bool
{
    auto const byte = static_cast<unsigned char>(value);
    return byte > 0x20U && byte < 0x7FU;
}

[[nodiscard]] auto is_localpart_character(char value) noexcept -> bool
{
    auto const byte = static_cast<unsigned char>(value);
    return std::isalnum(byte) != 0 || value == '.' || value == '_' || value == '-' || value == '=' || value == '/'
        || value == '+';
}

} // namespace

auto server_name_is_valid(std::string_view server_name) noexcept -> bool
{
    if (server_name.empty() || server_name.size() > 255U)
    {
        return false;
    }

    if (server_name.front() == '.' || server_name.back() == '.' || server_name.front() == '-' || server_name.back() == '-')
    {
        return false;
    }

    return std::ranges::all_of(server_name, [](char const value) {
        auto const byte = static_cast<unsigned char>(value);
        return std::isalnum(byte) != 0 || value == '.' || value == '-' || value == ':' || value == '[' || value == ']';
    });
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
        has_lower = has_lower || std::islower(byte) != 0;
        has_upper = has_upper || std::isupper(byte) != 0;
        has_digit = has_digit || std::isdigit(byte) != 0;
        has_symbol = has_symbol || (byte >= 0x21U && byte <= 0x7EU && std::isalnum(byte) == 0);
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
