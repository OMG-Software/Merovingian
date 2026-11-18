// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::oauth
{

// The lifetime of an OAuth 2.0 access token when `security.access_token_lifetime_ms` is 0, which means "no expiry" for
// a legacy token: one hour, the configuration's default. The spec says an OAuth access token MUST be short-lived, so
// it never goes without an expiry (ADR-0791).
inline constexpr auto default_access_token_lifetime_ms = std::int64_t{3'600'000};

// The lifetime in milliseconds of an access token issued or refreshed through the OAuth 2.0 token endpoint:
// `configured_lifetime_ms` (`security.access_token_lifetime_ms`, validated at start-up to 0 .. 30 days) when it is
// positive, otherwise default_access_token_lifetime_ms.
[[nodiscard]] constexpr auto access_token_lifetime_ms(std::int64_t configured_lifetime_ms) noexcept -> std::int64_t
{
    return configured_lifetime_ms > 0 ? configured_lifetime_ms : default_access_token_lifetime_ms;
}

// The token response's `expires_in` (RFC 6749 section 5.1, whole seconds) for a lifetime of `lifetime_ms`: rounded
// down, so the client refreshes no later than the token expires, and at least 1 for any positive lifetime.
[[nodiscard]] constexpr auto expires_in_seconds(std::int64_t lifetime_ms) noexcept -> std::int64_t
{
    if (lifetime_ms <= 0)
    {
        return 0;
    }
    auto const seconds = lifetime_ms / 1000;
    return seconds > 0 ? seconds : 1;
}

} // namespace merovingian::oauth
