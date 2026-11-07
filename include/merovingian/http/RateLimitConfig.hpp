// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/http/RateLimitPolicy.hpp"

#include <string>
#include <unordered_map>

namespace merovingian::http
{

struct RateLimitConfig final
{
    // Built-in per-endpoint refinements WITHIN a tier, seeded by
    // `default_client_rate_limit_config()` (keys/devices at 120/60s, search at
    // 20/60s, thumbnails at 240/60s) plus the built-in per-user login cap.
    // These are the secure defaults; operators do not write them directly.
    std::unordered_map<std::string, RateLimitPolicy> builtin_per_ip{};
    std::unordered_map<std::string, RateLimitPolicy> builtin_per_user{};
    // Operator per-endpoint/prefix overrides from the `client_rate_limits:`
    // config block, keyed by request target prefix (longest match wins).
    std::unordered_map<std::string, RateLimitPolicy> per_ip{};
    // Operator per-user overrides, keyed by target prefix. Empty map leaves
    // only the built-in per-user login cap. The cap is enforced on every
    // authenticated request for which a user_id is known; on unauthenticated
    // paths the per-user tier is skipped and the per-IP cap is the only limit.
    std::unordered_map<std::string, RateLimitPolicy> per_user{};
    // Operator per-tier overrides keyed by tier name (see
    // rate_limit_tier_name()). A tier override applies to every route
    // classified into that tier unless a more specific per-prefix override
    // exists.
    std::unordered_map<std::string, RateLimitPolicy> tier{};
    // Operator-tunable policy for routes in the generic tier
    // (`client_rate_limits.default_per_ip`). Also the ultimate fallback.
    RateLimitPolicy default_per_ip{600U, 60U};
};

} // namespace merovingian::http
