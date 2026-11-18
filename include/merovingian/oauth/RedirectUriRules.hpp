// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/oauth/ApplicationType.hpp"
#include "merovingian/oauth/ClientUri.hpp"
#include "merovingian/oauth/OAuthRefusal.hpp"
#include "merovingian/oauth/ParsedUri.hpp"

#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <variant>

namespace merovingian::oauth
{

// Redirect URI validation (spec "Redirect URI validation", RFC 8252 section 7; ADR-0770). Every URI is first read
// by ParsedUri, so none has a fragment, userinfo, a `%` in its host or a byte outside printable ASCII.

// Whether `uri` is an `https` URI (scheme in lower case) with an authority whose host is the client URI's host or a
// subdomain of it: equal, or ending in `.` followed by it, compared in ASCII lower case. `notexample.com` is not under
// `example.com`. Any port, path and query. The `web` redirect rule, and the rule for `policy_uri` and `tos_uri`.
[[nodiscard]] auto https_uri_is_on_client_host(ParsedUri const& uri, ClientUri const& client_uri) -> bool;

// Whether `uri` is a loopback redirect URI as a native client registers it: scheme `http`, host exactly
// `localhost`, `127.0.0.1` or `[::1]`, and no port.
[[nodiscard]] auto is_registrable_loopback_uri(ParsedUri const& uri) noexcept -> bool;

// `uri` checked for registration by a client of `type` whose client URI is `client_uri`, or a refusal with
// `invalid_redirect_uri` and fixed text.
//
//  - `web`: https_uri_is_on_client_host.
//  - `native`: (a) a private-use scheme equal to the reversed client URI host or starting with it followed by `.`,
//    compared in ASCII lower case, with no authority (no `//` after the scheme); or (b) is_registrable_loopback_uri;
//    or (c) a claimed `https` URI under the `web` rule.
[[nodiscard]] auto validate_redirect_uri(std::string_view uri, ApplicationType type, ClientUri const& client_uri)
    -> std::variant<ParsedUri, OAuthRefusal>;

// The `redirect_uri` of an authorisation or token request, read, when it matches one of `registered` (the URIs the
// client registered, each accepted by validate_redirect_uri): byte for byte, or, for a `native` client and a
// registered loopback URI, the same bytes with `:<port>` added after the host for any port 1 to 65535 written without
// a leading zero. std::nullopt when nothing matches or the request's URI cannot be read.
[[nodiscard]] auto match_redirect_uri(std::string_view requested, ApplicationType type,
                                      std::span<std::string const> registered) -> std::optional<ParsedUri>;

} // namespace merovingian::oauth
