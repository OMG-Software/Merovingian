// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string_view>

namespace merovingian::http
{

// The decision returned by RateLimitEngine::check. When allowed is true,
// the request may proceed. When allowed is false, the caller must
// reject with 429 M_LIMIT_EXCEEDED. The count fields are populated for
// both the allowed and denied outcomes so the log/audit emission can
// include them without a second engine call.
struct RateLimitDecision final
{
    bool allowed{true};
    std::uint32_t max_requests{0U};
    std::uint32_t window_seconds{0U};
    std::uint32_t requests_seen{0U};
    std::uint32_t per_ip_count{0U};
    std::uint32_t per_user_count{0U};
    std::uint32_t per_user_max{0U};
    std::uint32_t retry_after_ms{0U};
    // One of "", "per_ip_cap", "per_user_cap", "invalid_policy".
    std::string_view deny_reason{};
};

} // namespace merovingian::http
