// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/oauth/HandOffRedirect.hpp"

#include "merovingian/oauth/AsciiCase.hpp"
#include "merovingian/oauth/AuthorizationRedirect.hpp"
#include "merovingian/oauth/ResponseMode.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <variant>

namespace merovingian::oauth
{
namespace
{

    constexpr auto default_https_port = std::uint16_t{443U};
    constexpr auto login_token_parameter = std::string_view{"loginToken"};

    [[nodiscard]] auto is_loopback_host(std::string_view host) -> bool
    {
        auto const lower = ascii_lower(host);
        return lower == "localhost" || lower == "127.0.0.1" || lower == "[::1]";
    }

    // Whether `target`'s scheme (already in lower case as `scheme`) is one the hand-off may send a browser to.
    [[nodiscard]] auto scheme_is_accepted(ParsedUri const& target, std::string_view scheme) -> bool
    {
        if (scheme == "https")
        {
            return target.has_authority();
        }
        if (scheme == "http")
        {
            return target.has_authority() && is_loopback_host(target.host());
        }
        // A private-use scheme (RFC 8252 section 7.1) is a reversed DNS name with no authority (ADR-0802, amended):
        // `com.example.app://evil.example/` could otherwise reach an authority the allowlist entry `com.example.app:`
        // never named.
        return scheme.find('.') != std::string_view::npos && !target.has_authority();
    }

    [[nodiscard]] auto matches_entry(ParsedUri const& target, std::string_view scheme, std::string_view entry) -> bool
    {
        auto parsed = ParsedUri::read(entry);
        auto const* entry_uri = std::get_if<ParsedUri>(&parsed);
        if (entry_uri == nullptr)
        {
            return false;
        }
        if (!entry_uri->has_authority())
        {
            // A bare private-use scheme and its colon.
            return scheme == ascii_lower(entry_uri->scheme());
        }
        return scheme == "https" && target.has_authority() &&
               ascii_lower(target.host()) == ascii_lower(entry_uri->host()) &&
               target.port().value_or(default_https_port) == entry_uri->port().value_or(default_https_port);
    }

} // namespace

auto hand_off_redirect_target(std::string_view redirect_url, std::span<std::string const> allowlist)
    -> std::optional<ParsedUri>
{
    auto parsed = ParsedUri::read(redirect_url);
    auto* target = std::get_if<ParsedUri>(&parsed);
    if (target == nullptr)
    {
        return std::nullopt;
    }
    auto const scheme = ascii_lower(target->scheme());
    if (!scheme_is_accepted(*target, scheme))
    {
        return std::nullopt;
    }
    if (!allowlist.empty() && std::ranges::none_of(allowlist, [&](std::string const& entry) {
            return matches_entry(*target, scheme, entry);
        }))
    {
        return std::nullopt;
    }
    return std::move(*target);
}

auto hand_off_return_address(ParsedUri const& target, std::string_view login_token) -> std::optional<std::string>
{
    auto const& text = target.text();
    auto address = std::string{text.substr(0U, text.find('?'))};
    if (target.has_query())
    {
        auto kept = std::string{};
        auto query = std::string_view{target.query()};
        while (true)
        {
            auto const end = std::min(query.find('&'), query.size());
            auto const parameter = query.substr(0U, end);
            auto const name = parameter.substr(0U, std::min(parameter.find('='), parameter.size()));
            if (name != login_token_parameter)
            {
                if (!kept.empty())
                {
                    kept.push_back('&');
                }
                kept.append(parameter);
            }
            if (end == query.size())
            {
                break;
            }
            query.remove_prefix(end + 1U);
        }
        address.push_back('?');
        address.append(kept);
    }
    auto reread = ParsedUri::read(address);
    auto const* without_tokens = std::get_if<ParsedUri>(&reread);
    if (without_tokens == nullptr)
    {
        return std::nullopt;
    }
    auto const parameters = std::array{
        RedirectParameter{login_token_parameter, login_token}
    };
    return authorization_redirect_address(*without_tokens, ResponseMode::query, parameters);
}

} // namespace merovingian::oauth
