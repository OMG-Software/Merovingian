// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/core/CookieSameSite.hpp"
#include "merovingian/core/Error.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <variant>

// The only way this server writes a `Set-Cookie` value. Every cookie it sets is a `__Host-` cookie (RFC 6265bis
// section 4.1.3.2): `Secure`, `Path=/`, no `Domain`, so only this host over HTTPS can set or receive it and a sibling
// host under the same parent domain cannot overwrite it. It is also `HttpOnly`, so no script can read it.
namespace merovingian::core
{

// The prefix every name must start with.
inline constexpr auto host_cookie_prefix = std::string_view{"__Host-"};
// The longest Max-Age accepted: 400 days, the ceiling RFC 6265bis section 5.6.2 lets a user agent apply.
inline constexpr auto max_host_cookie_age_seconds = std::uint32_t{400U * 24U * 60U * 60U};
// The most bytes of name and value together: RFC 6265bis section 5.6 lets a user agent drop a larger cookie.
inline constexpr auto max_host_cookie_bytes = std::size_t{4096U};

// `name=value; Max-Age=<max_age_seconds>; Path=/; Secure; HttpOnly; SameSite=<same_site>`. Refused
// (ErrorCode::invalid_argument, fixed message) when `name` does not start with `__Host-` or is not an RFC 9110 token,
// `value` is empty or holds a byte outside the RFC 6265 cookie-octet set, the pair is over max_host_cookie_bytes, or
// `max_age_seconds` is 0 (use host_cookie_deletion) or over max_host_cookie_age_seconds. Nothing is repaired.
[[nodiscard]] auto host_cookie(std::string_view name, std::string_view value, CookieSameSite same_site,
                               std::uint32_t max_age_seconds) -> std::variant<std::string, Error>;

// The value that deletes cookie `name`: `name=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=<same_site>`. A
// browser only replaces a cookie set with the same name, path and prefix rules, so the attributes match host_cookie.
// Refused for a name host_cookie refuses.
[[nodiscard]] auto host_cookie_deletion(std::string_view name, CookieSameSite same_site)
    -> std::variant<std::string, Error>;

} // namespace merovingian::core
