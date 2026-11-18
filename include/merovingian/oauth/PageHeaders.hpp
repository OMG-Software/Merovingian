// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/oauth/ParsedUri.hpp"

#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace merovingian::oauth
{

// The fixed style block of every page: the text between `<style>` and `</style>`, byte for byte. Its SHA-256 is the
// only style source the Content-Security-Policy allows.
[[nodiscard]] auto page_style() noexcept -> std::string_view;

// The headers every page is sent with (ADR-0772):
//
//  - `Content-Type: text/html; charset=utf-8`;
//  - `Content-Security-Policy: default-src 'none'; style-src 'sha256-<base64 of SHA-256(page_style())>';
//    base-uri 'none'; frame-ancestors 'none'; form-action 'self'`. When hashing fails the style source is `'none'`,
//    so the page loses its style, never its policy;
//  - `X-Frame-Options: DENY`, `Referrer-Policy: same-origin` (ADR-0784), `Cache-Control: no-store`.
[[nodiscard]] auto page_headers() -> std::vector<std::pair<std::string, std::string>>;

// page_headers() for a page whose form post the server answers with a redirect to `redirect_target`, the client's
// validated redirect URI (match_redirect_uri): `form-action` also allows redirect_target.csp_source(), its origin
// (or its scheme and `:` for a private-use scheme), because Chromium applies `form-action` to the redirect that
// follows a form post. The source is built from the URI's scheme, host and port only, never from its text.
[[nodiscard]] auto page_headers(ParsedUri const& redirect_target) -> std::vector<std::pair<std::string, std::string>>;

} // namespace merovingian::oauth
