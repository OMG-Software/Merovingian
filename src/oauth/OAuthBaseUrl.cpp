// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/oauth/OAuthBaseUrl.hpp"

#include "merovingian/core/ErrorCode.hpp"

#include <utility>

namespace merovingian::oauth
{
namespace
{

    [[nodiscard]] auto without_trailing_slashes(std::string_view text) -> std::string
    {
        while (text.ends_with('/'))
        {
            text.remove_suffix(1U);
        }
        return std::string{text};
    }

} // namespace

OAuthBaseUrl::OAuthBaseUrl(ParsedUri uri)
    : m_uri{std::move(uri)}
    , m_prefix{without_trailing_slashes(m_uri.text())}
{
}

auto OAuthBaseUrl::read(std::string_view text) -> std::variant<OAuthBaseUrl, core::Error>
{
    auto parsed = ParsedUri::read(text);
    if (auto const* error = std::get_if<core::Error>(&parsed))
    {
        return core::Error{error->code(), "The base URL is not a valid URI."};
    }
    auto& uri = std::get<ParsedUri>(parsed);
    // The scheme is compared as written: the reader keeps its case, and a base URL is refused, never repaired.
    if (uri.scheme() != "https")
    {
        return core::Error{core::ErrorCode::parse_failure, "The base URL must use the https scheme."};
    }
    if (!uri.has_authority())
    {
        return core::Error{core::ErrorCode::parse_failure, "The base URL must name a host."};
    }
    if (uri.has_query())
    {
        return core::Error{core::ErrorCode::parse_failure, "The base URL must not have a query."};
    }
    return OAuthBaseUrl{std::move(uri)};
}

auto OAuthBaseUrl::issuer() const -> std::string
{
    return m_prefix + "/";
}

auto OAuthBaseUrl::url(PagePath path) const -> std::string
{
    return m_prefix + std::string{path.view()};
}

auto OAuthBaseUrl::uri() const noexcept -> ParsedUri const&
{
    return m_uri;
}

} // namespace merovingian::oauth
