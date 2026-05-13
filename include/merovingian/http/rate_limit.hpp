// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace merovingian::http
{

struct RateLimitPolicy final
{
    std::uint32_t max_requests{60U};
    std::uint32_t window_seconds{60U};
};

struct RateLimitState final
{
    std::uint32_t requests_seen{0U};
    std::uint32_t window_elapsed_seconds{0U};
};

[[nodiscard]] auto rate_limit_policy_is_valid(RateLimitPolicy const& policy) noexcept -> bool;
[[nodiscard]] auto request_is_rate_limited(RateLimitState state, RateLimitPolicy policy) noexcept -> bool;
[[nodiscard]] auto endpoint_default_rate_limit(std::string_view method, std::string_view target) noexcept
    -> RateLimitPolicy;
[[nodiscard]] auto rate_limit_summary(RateLimitPolicy const& policy) -> std::string;

} // namespace merovingian::http
