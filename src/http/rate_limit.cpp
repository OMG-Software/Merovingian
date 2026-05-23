// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/http/rate_limit.hpp"

#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"

#include <string>
#include <vector>

namespace merovingian::http
{
namespace
{

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields) -> void
    {
        LOG_DEBUG(observability::diagnostic_log_summary("rate_limit", event, std::move(fields)));
    }

    [[nodiscard]] auto starts_with(std::string_view value, std::string_view prefix) noexcept -> bool
    {
        return value.size() >= prefix.size() && value.substr(0U, prefix.size()) == prefix;
    }

} // namespace

auto rate_limit_policy_is_valid(RateLimitPolicy const& policy) noexcept -> bool
{
    return policy.max_requests > 0U && policy.window_seconds > 0U && policy.window_seconds <= 3600U;
}

auto request_is_rate_limited(RateLimitState state, RateLimitPolicy policy) -> bool
{
    if (!rate_limit_policy_is_valid(policy))
    {
        log_diagnostic("rate_limit.invalid_policy",
                       {{"max_requests",    std::to_string(policy.max_requests),   false},
                        {"window_seconds",  std::to_string(policy.window_seconds), false}});
        return true;
    }

    if (state.window_elapsed_seconds >= policy.window_seconds)
    {
        return false;
    }

    auto const limited = state.requests_seen >= policy.max_requests;
    if (limited)
    {
        log_diagnostic("rate_limit.exceeded",
                       {{"requests_seen",  std::to_string(state.requests_seen),          false},
                        {"max_requests",   std::to_string(policy.max_requests),           false},
                        {"window_seconds", std::to_string(policy.window_seconds),         false}});
    }
    return limited;
}

auto endpoint_default_rate_limit(std::string_view method, std::string_view target) noexcept -> RateLimitPolicy
{
    if (method == "POST" &&
        (starts_with(target, "/_matrix/client/v3/login") || starts_with(target, "/_matrix/client/v3/register")))
    {
        return {5U, 60U};
    }

    if (starts_with(target, "/_matrix/client/v3/keys/") || starts_with(target, "/_matrix/client/v3/devices"))
    {
        return {30U, 60U};
    }

    if (starts_with(target, "/_matrix/media/"))
    {
        return {20U, 60U};
    }

    if (starts_with(target, "/_matrix/federation/"))
    {
        return {120U, 60U};
    }

    return {60U, 60U};
}

auto rate_limit_summary(RateLimitPolicy const& policy) -> std::string
{
    return "HTTP rate limit: max_requests=" + std::to_string(policy.max_requests) +
           " window_seconds=" + std::to_string(policy.window_seconds);
}

} // namespace merovingian::http
