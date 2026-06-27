// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace merovingian::http
{

struct RateLimitPolicy final
{
    std::uint32_t max_requests{90U};
    std::uint32_t window_seconds{60U};
};

struct RateLimitState final
{
    std::uint32_t requests_seen{0U};
    std::uint32_t window_elapsed_seconds{0U};
};

[[nodiscard]] auto rate_limit_policy_is_valid(RateLimitPolicy const& policy) noexcept -> bool;
[[nodiscard]] auto request_is_rate_limited(RateLimitState state, RateLimitPolicy policy) -> bool;
[[nodiscard]] auto endpoint_default_rate_limit(std::string_view method, std::string_view target) noexcept
    -> RateLimitPolicy;
[[nodiscard]] auto rate_limit_summary(RateLimitPolicy const& policy) -> std::string;

struct RateLimitConfig final
{
    // Per-IP cap, keyed by request target prefix (e.g. "/_matrix/client/v3/register").
    // Operators override any entry via the `client_rate_limits:` config block.
    std::unordered_map<std::string, RateLimitPolicy> per_ip{};
    // Per-user cap, currently only populated for /login. Empty map
    // disables the per-user tier entirely. The cap is enforced on
    // every authenticated login attempt; on the unauthenticated path
    // (no user_id available yet) the per-user tier is skipped and the
    // per-IP cap is the only limit.
    std::unordered_map<std::string, RateLimitPolicy> per_user{};
    // Fallback for target prefixes not in the per_ip map.
    RateLimitPolicy default_per_ip{90U, 60U};
};

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
    // One of "", "per_ip_cap", "per_user_cap", "invalid_policy".
    std::string_view deny_reason{};
};

// The engine. Templated on the clock so tests can supply a
// std::chrono::steady_clock::time_point-producing callable. In
// production the clock is a thin wrapper over std::chrono::steady_clock.
template <typename Clock>
class RateLimitEngine final
{
public:
    using TimePoint = std::chrono::steady_clock::time_point;

    // The clock is borrowed, not owned. The caller must keep the
    // clock object alive for the lifetime of the engine. In
    // production the engine is a member of ClientServerRuntime, so
    // the clock is a member of the runtime too. In tests the
    // caller mutates the clock object directly; the engine sees
    // the updated value on the next check() call.
    RateLimitEngine(RateLimitConfig config, Clock& clock) noexcept
        : m_config{std::move(config)}
        , m_clock{&clock}
    {
    }

    [[nodiscard]] auto resolve_per_ip_policy(std::string_view target) const -> std::optional<RateLimitPolicy>
    {
        auto const* policy = lookup_policy(m_config.per_ip, target);
        if (policy == nullptr)
        {
            policy = &m_config.default_per_ip;
        }
        if (!rate_limit_policy_is_valid(*policy))
        {
            return std::nullopt;
        }
        return *policy;
    }

    [[nodiscard]] auto resolve_per_user_policy(std::string_view target) const -> std::optional<RateLimitPolicy>
    {
        auto const* policy = lookup_policy(m_config.per_user, target);
        if (policy == nullptr || !rate_limit_policy_is_valid(*policy))
        {
            return std::nullopt;
        }
        return *policy;
    }

    // Consumes one request against the per-IP bucket (keyed by
    // `ip_bucket`) and the per-user bucket (keyed by `user_bucket`,
    // which may be empty when no user is known yet). The window
    // rolls over on the wall-clock seconds set by the resolved
    // policy. Returns a RateLimitDecision with all count fields
    // populated for the audit row.
    auto check(std::string_view ip_bucket, std::string_view target, std::string_view user_bucket) -> RateLimitDecision
    {
        auto const now = (*m_clock)();
        auto const per_ip = resolve_per_ip_policy(target);
        auto const per_user = resolve_per_user_policy(target);

        if (!per_ip.has_value() && !per_user.has_value())
        {
            return RateLimitDecision{.allowed = true, .deny_reason = "invalid_policy"};
        }

        auto const ip_decision = ip_bucket.empty() ? RateLimitDecision{true, 0U, 0U, 0U, 0U, 0U, 0U, ""}
                                                   : check_bucket(m_ip_buckets, ip_bucket, per_ip, now);
        auto const user_decision = user_bucket.empty() ? RateLimitDecision{true, 0U, 0U, 0U, 0U, 0U, 0U, ""}
                                                       : check_bucket(m_user_buckets, user_bucket, per_user, now);

        if (!user_decision.allowed)
        {
            auto d = user_decision;
            d.deny_reason = "per_user_cap";
            d.per_ip_count = ip_decision.requests_seen;
            d.per_user_count = user_decision.requests_seen;
            d.per_user_max = per_user ? per_user->max_requests : 0U;
            return d;
        }
        if (!ip_decision.allowed)
        {
            auto d = ip_decision;
            d.deny_reason = "per_ip_cap";
            d.per_user_count = user_decision.requests_seen;
            d.per_user_max = per_user ? per_user->max_requests : 0U;
            return d;
        }

        return RateLimitDecision{
            .allowed = true,
            .max_requests = per_ip ? per_ip->max_requests : 0U,
            .window_seconds = per_ip ? per_ip->window_seconds : 0U,
            .requests_seen = ip_decision.requests_seen,
            .per_ip_count = ip_decision.requests_seen,
            .per_user_count = user_decision.requests_seen,
            .per_user_max = per_user ? per_user->max_requests : 0U,
            .deny_reason = "",
        };
    }

    // Wipes all bucket state. Called on server restart to honour the
    // operator request that "restart should reset the rate counter".
    auto reset() noexcept -> void
    {
        m_ip_buckets.clear();
        m_user_buckets.clear();
    }

private:
    struct Bucket final
    {
        std::string key{};
        std::uint32_t count{0U};
        TimePoint window_start{};
    };

    [[nodiscard]] static auto lookup_policy(std::unordered_map<std::string, RateLimitPolicy> const& table,
                                            std::string_view target) -> RateLimitPolicy const*
    {
        // Find the longest matching prefix. This lets a config entry
        // for "/_matrix/client/v3/login" match "/_matrix/client/v3/login/foo".
        auto best = static_cast<RateLimitPolicy const*>(nullptr);
        auto best_len = std::size_t{0U};
        for (auto const& [key, policy] : table)
        {
            if (target.size() >= key.size() && target.substr(0U, key.size()) == key && key.size() > best_len)
            {
                best = &policy;
                best_len = key.size();
            }
        }
        return best;
    }

    [[nodiscard]] auto check_bucket(std::vector<Bucket>& table, std::string_view bucket_key,
                                    std::optional<RateLimitPolicy> const& policy, TimePoint now) -> RateLimitDecision
    {
        if (!policy.has_value() || bucket_key.empty())
        {
            return RateLimitDecision{true, 0U, 0U, 0U, 0U, 0U, 0U, ""};
        }
        auto it = std::ranges::find_if(table, [bucket_key](Bucket const& b) {
            return b.key == bucket_key;
        });
        if (it == table.end())
        {
            table.push_back({std::string{bucket_key}, 1U, now});
            return RateLimitDecision{true, policy->max_requests, policy->window_seconds, 1U, 1U, 0U, 0U, ""};
        }
        if (now - it->window_start >= std::chrono::seconds{policy->window_seconds})
        {
            it->count = 0U;
            it->window_start = now;
        }
        if (it->count >= policy->max_requests)
        {
            return RateLimitDecision{false, policy->max_requests, policy->window_seconds, it->count, it->count, 0U,
                                     0U,    "per_ip_cap"};
        }
        ++it->count;
        return RateLimitDecision{true, policy->max_requests, policy->window_seconds, it->count, it->count, 0U, 0U, ""};
    }

    RateLimitConfig m_config{};
    Clock* m_clock{nullptr};
    std::vector<Bucket> m_ip_buckets{};
    std::vector<Bucket> m_user_buckets{};
};

} // namespace merovingian::http
