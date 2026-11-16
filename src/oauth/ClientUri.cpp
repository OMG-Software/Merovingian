// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/oauth/ClientUri.hpp"

#include "merovingian/core/ErrorCode.hpp"
#include "merovingian/oauth/AsciiCase.hpp"
#include "merovingian/oauth/OAuthErrorCodes.hpp"

#include <algorithm>
#include <string_view>
#include <utility>

namespace merovingian::oauth
{
namespace
{

    [[nodiscard]] auto refuse(core::ErrorCode code, char const* message) -> OAuthRefusal
    {
        return OAuthRefusal{
            std::string{error_invalid_client_metadata},
            core::Error{code, message}
        };
    }

    // `a.b.c` gives `c.b.a`. The host has no empty label (ParsedUri), so every label is kept.
    [[nodiscard]] auto reverse_labels(std::string_view host) -> std::string
    {
        auto reversed = std::string{};
        reversed.reserve(host.size());
        auto rest = host;
        while (!rest.empty())
        {
            auto const dot = rest.rfind('.');
            auto const label = dot == std::string_view::npos ? rest : rest.substr(dot + 1U);
            if (!reversed.empty())
            {
                reversed.push_back('.');
            }
            reversed.append(label);
            rest = dot == std::string_view::npos ? std::string_view{} : rest.substr(0U, dot);
        }
        return reversed;
    }

    // The WHATWG URL Standard's "ends in a number checker" for the last label: all ASCII digits, or `0x` / `0X`
    // followed only by hex digits (`0x` alone included). A browser reads such a host as an IPv4 address (`0x7f.1` is
    // 127.0.0.1 to it), so it is never a DNS name here.
    [[nodiscard]] auto ends_in_a_number(std::string_view label) noexcept -> bool
    {
        auto const digits = [](std::string_view text, auto&& accepted) noexcept {
            return std::ranges::all_of(text, accepted);
        };
        if (!label.empty() && digits(label, [](char value) noexcept {
                return value >= '0' && value <= '9';
            }))
        {
            return true;
        }
        return label.size() >= 2U && label[0] == '0' && (label[1] == 'x' || label[1] == 'X') &&
               digits(label.substr(2U), [](char value) noexcept {
                   return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f') ||
                          (value >= 'A' && value <= 'F');
               });
    }

} // namespace

ClientUri::ClientUri(ParsedUri uri)
    : m_uri{std::move(uri)}
    , m_host_lower{ascii_lower(m_uri.host())}
    , m_reversed_host_lower{reverse_labels(m_host_lower)}
{
}

auto ClientUri::read(std::string_view text) -> std::variant<ClientUri, OAuthRefusal>
{
    auto parsed = ParsedUri::read(text);
    if (auto const* error = std::get_if<core::Error>(&parsed))
    {
        return refuse(error->code(), "The client_uri is not a valid URI.");
    }
    auto& uri = std::get<ParsedUri>(parsed);
    if (uri.scheme() != "https" || !uri.has_authority())
    {
        return refuse(core::ErrorCode::parse_failure, "The client_uri must be an https URL.");
    }
    auto const host = ascii_lower(uri.host());
    if (host.starts_with('['))
    {
        return refuse(core::ErrorCode::parse_failure, "The client_uri host must be a DNS name.");
    }
    auto const last_dot = host.rfind('.');
    if (last_dot == std::string::npos)
    {
        return refuse(core::ErrorCode::parse_failure, "The client_uri host must have at least two labels.");
    }
    if (ends_in_a_number(std::string_view{host}.substr(last_dot + 1U)))
    {
        return refuse(core::ErrorCode::parse_failure, "The client_uri host must be a DNS name.");
    }
    if (std::string_view{host}.substr(last_dot + 1U) == "localhost")
    {
        return refuse(core::ErrorCode::parse_failure, "The client_uri host must not be a loopback name.");
    }
    return ClientUri{std::move(uri)};
}

auto ClientUri::uri() const noexcept -> ParsedUri const&
{
    return m_uri;
}

auto ClientUri::host_lower() const noexcept -> std::string const&
{
    return m_host_lower;
}

auto ClientUri::reversed_host_lower() const noexcept -> std::string const&
{
    return m_reversed_host_lower;
}

} // namespace merovingian::oauth
