// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/http/rate_limit.hpp"

#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"

#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace merovingian::http
{
namespace
{

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields,
                        observability::LogEventSeverity severity = observability::LogEventSeverity::debug) -> void
    {
        observability::log_diagnostic("rate_limit", event, fields, severity);
    }

    [[nodiscard]] auto starts_with(std::string_view value, std::string_view prefix) noexcept -> bool
    {
        return value.size() >= prefix.size() && value.substr(0U, prefix.size()) == prefix;
    }

    // Built-in per-endpoint refinements WITHIN a tier. These are the routes
    // whose secure default is tighter than their tier's default. Kept in
    // sync with the literal maps in default_client_rate_limit_config() —
    // both places list the same three routes.
    [[nodiscard]] auto builtin_per_ip_refinement(std::string_view target) noexcept -> std::optional<RateLimitPolicy>
    {
        if (starts_with(target, "/_matrix/client/v3/keys/") || starts_with(target, "/_matrix/client/v3/devices"))
        {
            return RateLimitPolicy{30U, 60U};
        }
        if (starts_with(target, "/_matrix/client/v3/search"))
        {
            return RateLimitPolicy{20U, 60U};
        }
        return std::nullopt;
    }

} // namespace

auto rate_limit_tier_for(std::string_view target) noexcept -> RateLimitTier
{
    // One greppable classification table. Method-agnostic on purpose: a GET
    // against /login is the same enumeration surface as a POST, and the
    // /requestToken family spans several parents
    // (/account/3pid/email|msisdn/requestToken, /register/*/requestToken),
    // so it is matched by suffix.
    if (starts_with(target, "/_matrix/client/v3/login") || starts_with(target, "/_matrix/client/v3/refresh") ||
        starts_with(target, "/_matrix/client/v3/register") || target.find("/requestToken") != std::string_view::npos)
    {
        return RateLimitTier::auth_sensitive;
    }
    if (starts_with(target, "/_matrix/media/") || starts_with(target, "/_matrix/client/v1/media/"))
    {
        return RateLimitTier::media;
    }
    if (starts_with(target, "/_matrix/client/v3/sync") ||
        starts_with(target, "/_matrix/client/unstable/org.matrix.msc4186/sync") ||
        starts_with(target, "/_matrix/client/unstable/org.matrix.simplified_msc3575/sync"))
    {
        return RateLimitTier::sync;
    }
    if (starts_with(target, "/_matrix/federation/"))
    {
        return RateLimitTier::federation;
    }
    if (starts_with(target, "/_merovingian/admin/"))
    {
        return RateLimitTier::admin;
    }
    return RateLimitTier::generic;
}

auto rate_limit_tier_name(RateLimitTier tier) noexcept -> std::string_view
{
    switch (tier)
    {
    case RateLimitTier::auth_sensitive:
        return "auth_sensitive";
    case RateLimitTier::media:
        return "media";
    case RateLimitTier::sync:
        return "sync";
    case RateLimitTier::federation:
        return "federation";
    case RateLimitTier::admin:
        return "admin";
    case RateLimitTier::generic:
        return "generic";
    }
    std::unreachable();
}

auto rate_limit_tier_from_name(std::string_view name) noexcept -> std::optional<RateLimitTier>
{
    if (name == "auth_sensitive")
    {
        return RateLimitTier::auth_sensitive;
    }
    if (name == "media")
    {
        return RateLimitTier::media;
    }
    if (name == "sync")
    {
        return RateLimitTier::sync;
    }
    if (name == "federation")
    {
        return RateLimitTier::federation;
    }
    if (name == "admin")
    {
        return RateLimitTier::admin;
    }
    if (name == "generic")
    {
        return RateLimitTier::generic;
    }
    return std::nullopt;
}

auto rate_limit_tier_default(RateLimitTier tier) noexcept -> RateLimitPolicy
{
    switch (tier)
    {
    case RateLimitTier::auth_sensitive:
    case RateLimitTier::media:
        return {20U, 60U};
    case RateLimitTier::sync:
    case RateLimitTier::generic:
        return {90U, 60U};
    case RateLimitTier::federation:
        return {120U, 60U};
    case RateLimitTier::admin:
        return {30U, 60U};
    }
    std::unreachable();
}

auto rate_limit_policy_is_valid(RateLimitPolicy const& policy) noexcept -> bool
{
    return policy.max_requests > 0U && policy.window_seconds > 0U && policy.window_seconds <= 3600U;
}

auto request_is_rate_limited(RateLimitState state, RateLimitPolicy policy) -> bool
{
    if (!rate_limit_policy_is_valid(policy))
    {
        log_diagnostic("rate_limit.invalid_policy",
                       {
                           {"max_requests",   std::to_string(policy.max_requests),   false},
                           {"window_seconds", std::to_string(policy.window_seconds), false}
        });
        return true;
    }

    if (state.window_elapsed_seconds >= policy.window_seconds)
    {
        return false;
    }

    auto const limited = state.requests_seen >= policy.max_requests;
    if (limited)
    {
        log_diagnostic("rate_limit.exceeded", {
                                                  {"requests_seen",  std::to_string(state.requests_seen),   false},
                                                  {"max_requests",   std::to_string(policy.max_requests),   false},
                                                  {"window_seconds", std::to_string(policy.window_seconds), false}
        });
    }
    return limited;
}

auto endpoint_default_rate_limit(std::string_view method, std::string_view target) noexcept -> RateLimitPolicy
{
    // `method` is retained for source compatibility; classification is
    // method-agnostic (see rate_limit_tier_for). Built-in refinements win
    // over the tier default so keys/devices keep 30/min and search 20/min.
    std::ignore = method;
    if (auto const refinement = builtin_per_ip_refinement(target); refinement.has_value())
    {
        return *refinement;
    }
    return rate_limit_tier_default(rate_limit_tier_for(target));
}

auto default_client_rate_limit_config() noexcept -> RateLimitConfig
{
    // Design-doc defaults (0.5.0), now expressed through tiers: 20/min per IP
    // for the auth-sensitive tier (login/register/refresh/requestToken), 5/min
    // per user for login, 30/min for keys/devices, 20/min for media and
    // search, 120/min for federation routes on the client listener, 90/min
    // for sync and everything else, 30/min for /_merovingian/admin/* —
    // operator-only, low-volume, but still throttled against brute-force
    // token guessing. Search gets the same 20/min-per-IP tier as media: like
    // media, each request can do real work (a bounded in-memory scan of the
    // caller's joined-room events, capped by
    // ClientApiLimits::max_search_events_scanned) rather than a cheap lookup,
    // so it is throttled tighter than the generic fallback. The tier defaults
    // themselves live in rate_limit_tier_default(); only the refinements that
    // are tighter than their tier are seeded here.
    return RateLimitConfig{
        .builtin_per_ip =
            {
                             {"/_matrix/client/v3/keys/", {30U, 60U}},
                             {"/_matrix/client/v3/devices", {30U, 60U}},
                             {"/_matrix/client/v3/search", {20U, 60U}},
                             },
        .builtin_per_user =
            {
                             {"/_matrix/client/v3/login", {5U, 60U}},
                             },
        .default_per_ip = {90U, 60U},
    };
}

auto rate_limit_summary(RateLimitPolicy const& policy) -> std::string
{
    return "HTTP rate limit: max_requests=" + std::to_string(policy.max_requests) +
           " window_seconds=" + std::to_string(policy.window_seconds);
}

} // namespace merovingian::http
