// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/http/rate_limit.hpp"

#include <string>
#include <unordered_map>

namespace merovingian::config
{

// Per-endpoint rate-limit policies. The values populate
// `http::RateLimitEngine` at `start_client_server()` time; restart
// required (see `src/config/reload_policy.cpp`). Defaults are expressed
// through the route tiers in `http::rate_limit_tier_for()`:
// 20/min per IP for the auth-sensitive tier (/login, /register, /refresh
// and the */requestToken family), 5/min per user for /login, 120/min for
// keys/devices and media, 20/min for search, 240/min for thumbnails,
// 3000/min for sync/federation routes, 600/min for generic traffic.
struct ClientRateLimitsConfig final
{
    std::unordered_map<std::string, http::RateLimitPolicy> per_ip{};
    std::unordered_map<std::string, http::RateLimitPolicy> per_user{};
    // Per-tier overrides keyed by tier name (auth_sensitive, media, sync,
    // federation, admin, generic). Validated against
    // `http::rate_limit_tier_from_name()` so a typo is a parse finding.
    std::unordered_map<std::string, http::RateLimitPolicy> tier{};
    http::RateLimitPolicy default_per_ip{600U, 60U};
};

} // namespace merovingian::config
