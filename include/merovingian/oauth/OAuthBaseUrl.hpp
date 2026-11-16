// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/core/Error.hpp"
#include "merovingian/oauth/PagePath.hpp"
#include "merovingian/oauth/ParsedUri.hpp"

#include <string>
#include <string_view>
#include <variant>

namespace merovingian::oauth
{

// `server.public_baseurl` read as the base of every absolute address the OAuth 2.0 API publishes (ADR-0773). It
// exists only through read(), so it always satisfies these rules: a ParsedUri (so no userinfo, no fragment, printable
// ASCII only) with the scheme `https` in lower case, an authority, and no query. A port and a path are allowed.
//
// Every absolute URL the API publishes is built here, by url(), and the issuer by issuer(). Nothing else joins a
// path to the base URL.
class OAuthBaseUrl final
{
public:
    // `text` as the base URL, or why not, as fixed text that never quotes the input.
    // ErrorCode::parse_failure: a rule above is broken. ErrorCode::invalid_argument: ParsedUri's length cap.
    [[nodiscard]] static auto read(std::string_view text) -> std::variant<OAuthBaseUrl, core::Error>;

    // The issuer identifier: the base URL with exactly one trailing slash (`https://h` and `https://h/` both give
    // `https://h/`; `https://h/m` gives `https://h/m/`). RFC 8414 requires `https` and no query or fragment.
    [[nodiscard]] auto issuer() const -> std::string;
    // The absolute URL of `path` on this server: the base URL with its trailing slashes removed, then `path`
    // (`https://h/m/` and `/_merovingian/oauth2/token` give `https://h/m/_merovingian/oauth2/token`).
    [[nodiscard]] auto url(PagePath path) const -> std::string;
    // The base URL as read.
    [[nodiscard]] auto uri() const noexcept -> ParsedUri const&;

private:
    explicit OAuthBaseUrl(ParsedUri uri);

    ParsedUri m_uri;
    // The text without trailing slashes, the common prefix of issuer() and url().
    std::string m_prefix{};
};

} // namespace merovingian::oauth
