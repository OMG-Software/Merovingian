// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/oauth/ScopeParser.hpp"

#include "merovingian/auth/Identity.hpp"
#include "merovingian/core/ErrorCode.hpp"
#include "merovingian/oauth/OAuthErrorCodes.hpp"

#include <algorithm>
#include <optional>
#include <string>

namespace merovingian::oauth
{
namespace
{

    [[nodiscard]] auto refuse(core::ErrorCode code, char const* message) -> OAuthRefusal
    {
        return OAuthRefusal{
            std::string{error_invalid_scope},
            core::Error{code, message}
        };
    }

    // RFC 6749 section 3.3 scope-token characters.
    [[nodiscard]] auto is_scope_token_char(char value) noexcept -> bool
    {
        auto const byte = static_cast<unsigned char>(value);
        return byte == 0x21U || (byte >= 0x23U && byte <= 0x5BU) || (byte >= 0x5DU && byte <= 0x7EU);
    }

    [[nodiscard]] auto is_unreserved(char value) noexcept -> bool
    {
        return (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z') || (value >= '0' && value <= '9') ||
               value == '-' || value == '.' || value == '_' || value == '~';
    }

} // namespace

auto oauth_device_id_is_valid(std::string_view device_id) noexcept -> bool
{
    return device_id.size() >= min_oauth_device_id_chars && auth::device_id_is_valid(device_id) &&
           std::ranges::all_of(device_id, is_unreserved);
}

auto parse_scope(std::string_view scope) -> std::variant<GrantedScope, OAuthRefusal>
{
    if (scope.size() > max_scope_bytes)
    {
        return refuse(core::ErrorCode::invalid_argument, "The scope is too long.");
    }
    if (scope.empty())
    {
        return refuse(core::ErrorCode::parse_failure, "The scope is empty.");
    }

    auto has_api = false;
    auto device_tokens = std::size_t{0U};
    auto device_id = std::optional<std::string_view>{};
    auto tokens = std::size_t{0U};

    auto rest = scope;
    while (true)
    {
        auto const space = rest.find(' ');
        auto const token = rest.substr(0U, space);
        if (token.empty())
        {
            return refuse(core::ErrorCode::parse_failure, "The scope has an empty token.");
        }
        if (!std::ranges::all_of(token, is_scope_token_char))
        {
            return refuse(core::ErrorCode::parse_failure, "The scope holds a character a scope token cannot.");
        }
        ++tokens;
        if (tokens > max_scope_tokens)
        {
            return refuse(core::ErrorCode::invalid_argument, "The scope has too many tokens.");
        }

        if (token == scope_token_api_all)
        {
            has_api = true;
        }
        else if (token.starts_with(scope_token_device_prefix))
        {
            ++device_tokens;
            device_id = token.substr(scope_token_device_prefix.size());
        }

        if (space == std::string_view::npos)
        {
            break;
        }
        rest = rest.substr(space + 1U);
    }

    if (!has_api)
    {
        return refuse(core::ErrorCode::parse_failure, "The scope must hold urn:matrix:client:api:*.");
    }
    if (device_tokens != 1U || !device_id.has_value())
    {
        return refuse(core::ErrorCode::parse_failure,
                      "The scope must hold exactly one urn:matrix:client:device: token.");
    }
    if (!oauth_device_id_is_valid(*device_id))
    {
        return refuse(core::ErrorCode::parse_failure,
                      "The device ID must be at least 10 characters of A-Z a-z 0-9 - . _ ~.");
    }

    auto granted = GrantedScope{};
    granted.device_id = std::string{*device_id};
    granted.scope = std::string{scope_token_api_all};
    granted.scope.push_back(' ');
    granted.scope.append(scope_token_device_prefix);
    granted.scope.append(granted.device_id);
    return granted;
}

} // namespace merovingian::oauth
