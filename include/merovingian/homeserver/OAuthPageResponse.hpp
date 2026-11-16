// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/LocalHttpRequest.hpp"
#include "merovingian/homeserver/LocalHttpResponse.hpp"
#include "merovingian/oauth/HtmlText.hpp"
#include "merovingian/oauth/Page.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace merovingian::homeserver
{

// Module-internal: what the server's own HTML pages (the OAuth 2.0 authorisation pages, `OAuthAuthorization.cpp`, and
// the account pages, `AccountPage.cpp`) share to answer and to read a browser's request. Not public API.

// A page answer: the rendered page with `headers` (normally `oauth::page_headers()`, ADR-0772, ADR-0784) and the page
// mark, so the boundary adds no CORS header and `wrap()` leaves it alone (ADR-0785).
[[nodiscard]] auto oauth_page_response(std::uint16_t status, oauth::Page const& page,
                                       std::vector<std::pair<std::string, std::string>> headers) -> LocalHttpResponse;

// `page` with `status` and `oauth::page_headers()`.
[[nodiscard]] auto oauth_plain_page(std::uint16_t status, oauth::Page const& page) -> LocalHttpResponse;

// `oauth::error_page(title, message)` with `status` and `oauth::page_headers()`.
[[nodiscard]] auto oauth_error_page_response(std::uint16_t status, oauth::HtmlText title,
                                             oauth::HtmlText const& message) -> LocalHttpResponse;

// The query of a request target, without the `?`; empty when there is none.
[[nodiscard]] auto request_target_query(std::string_view target) noexcept -> std::string_view;

// The one value of header `name`, or nullopt when it is absent or sent more than once (a repeated `Origin`,
// `Sec-Fetch-Site`, `Content-Type` or `Cookie` is treated as absent, never resolved).
[[nodiscard]] auto single_request_header(LocalHttpRequest const& request, std::string_view name)
    -> std::optional<std::string_view>;

// Whether `value` has the form `make_oauth_secret` mints: 64 lower-case hex digits.
[[nodiscard]] auto is_oauth_secret_text(std::string_view value) noexcept -> bool;

// The value of cookie `cookie_name` when the request carries exactly one `Cookie` header, it parses, and the value has
// the form of a minted secret (`is_oauth_secret_text`). Anything else is nullopt: never a value to look up.
[[nodiscard]] auto request_secret_cookie(LocalHttpRequest const& request, std::string_view cookie_name)
    -> std::optional<std::string>;

// `Retry-After` in whole seconds, rounded up, at least one.
[[nodiscard]] auto retry_after_seconds(std::uint32_t retry_after_ms) noexcept -> std::uint32_t;

} // namespace merovingian::homeserver
