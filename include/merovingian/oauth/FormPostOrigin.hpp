// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/oauth/OAuthBaseUrl.hpp"

#include <optional>
#include <string>
#include <string_view>

namespace merovingian::oauth
{

// The origin a browser names in `Origin` for a page of this server (ADR-0784): `https://`, the base URL's host in
// lower case, and `:<port>` only when the base URL names a port other than 443. A browser serialises an origin so
// (RFC 6454 section 6.1: the default port is left out), so this is the one form compared.
[[nodiscard]] auto form_post_origin(OAuthBaseUrl const& base_url) -> std::string;

// Whether a form post to an OAuth 2.0 page came from this server's own pages (ADR-0784). `origin` and
// `sec_fetch_site` are the request's `Origin` and `Sec-Fetch-Site` header values, nullopt when absent.
//  - `Origin` must be present and equal `form_post_origin(base_url)` byte for byte. Absent, `null`, another scheme,
//    host or port, an explicit `:443`, a trailing slash or a different case is refused.
//  - `Sec-Fetch-Site`, when present, must be exactly `same-origin`. Absent is accepted: not every browser sends it.
// Anything else is refused. Pure: no state, no I/O.
[[nodiscard]] auto form_post_origin_is_accepted(OAuthBaseUrl const& base_url, std::optional<std::string_view> origin,
                                                std::optional<std::string_view> sec_fetch_site) -> bool;

} // namespace merovingian::oauth
