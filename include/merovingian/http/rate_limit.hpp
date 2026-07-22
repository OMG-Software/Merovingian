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

    [[nodiscard]] auto operator==(RateLimitPolicy const& other) const noexcept -> bool = default;
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
    // `default_client_rate_limit_config()` pre-populates this with design-doc
    // defaults; operators override any entry via the `client_rate_limits:`
    // config block.
    std::unordered_map<std::string, RateLimitPolicy> per_ip{};
    // Per-user cap, currently populated for /login by default. Empty map
    // disables the per-user tier entirely. The cap is enforced on
    // every authenticated request for which a user_id is known; on
    // unauthenticated paths the per-user tier is skipped and the
    // per-IP cap is the only limit.
    std::unordered_map<std::string, RateLimitPolicy> per_user{};
    // Fallback for target prefixes not in the per_ip map.
    RateLimitPolicy default_per_ip{90U, 60U};
};

[[nodiscard]] auto default_client_rate_limit_config() noexcept -> RateLimitConfig;

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
            // Fail closed: a policy that cannot be resolved (missing config entry
            // combined with an invalid default, or a default that fails
            // rate_limit_policy_is_valid()) must never be treated as "no limit".
            // Matches the fail-closed behaviour of the standalone
            // request_is_rate_limited() helper.
            return RateLimitDecision{.allowed = false, .deny_reason = "invalid_policy"};
        }

        auto const ip_decision = ip_bucket.empty() ? RateLimitDecision{true, 0U, 0U, 0U, 0U, 0U, 0U, 0U, ""}
                                                   : check_bucket(m_ip_buckets, ip_bucket, per_ip, now);
        auto const user_decision = user_bucket.empty() ? RateLimitDecision{true, 0U, 0U, 0U, 0U, 0U, 0U, 0U, ""}
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

    // Exposes bucket-table sizes so tests can assert the bound in #427 holds
    // (sustained distinct keys do not grow the table past kMaxBucketsPerTable)
    // without depending on internal layout.
    [[nodiscard]] auto ip_bucket_count() const noexcept -> std::size_t
    {
        return m_ip_buckets.size();
    }

    [[nodiscard]] auto user_bucket_count() const noexcept -> std::size_t
    {
        return m_user_buckets.size();
    }

private:
    struct Bucket final
    {
        std::uint32_t count{0U};
        // The window length in force when this bucket was created/reset.
        // Stored per-bucket (not just looked up from the caller's current
        // policy) because entries in the same table can belong to different
        // routes with different configured windows, and eviction sweeps need
        // to judge staleness without re-resolving each bucket's policy.
        std::uint32_t window_seconds{0U};
        TimePoint window_start{};
    };

    // Bounds each bucket table so an attacker who can force many distinct keys
    // (e.g. rotating a client-supplied X-Forwarded-For value through a trusted
    // proxy) cannot grow memory or per-check scan cost without bound. Set well
    // above any plausible legitimate concurrent-key count; the eviction sweep
    // below only runs when a brand-new key arrives while a table is already at
    // capacity, not on every check().
    static constexpr std::size_t kMaxBucketsPerTable = 100'000U;

    // Makes room in `table` for a new key: first evicts entries whose window
    // is clearly expired (more than twice its own window length old, safely
    // stale under any clock skew or missed sweep), then — if still at
    // capacity — evicts the single least-recently-touched entry. This bounds
    // table growth under sustained distinct-key pressure (see #427).
    static auto evict_to_make_room(std::unordered_map<std::string, Bucket>& table, TimePoint now) -> void
    {
        if (table.size() < kMaxBucketsPerTable)
        {
            return;
        }
        for (auto it = table.begin(); it != table.end();)
        {
            auto const stale_after = std::chrono::seconds{static_cast<std::int64_t>(it->second.window_seconds) * 2};
            if (now - it->second.window_start >= stale_after)
            {
                it = table.erase(it);
            }
            else
            {
                ++it;
            }
        }
        if (table.size() < kMaxBucketsPerTable)
        {
            return;
        }
        auto oldest = table.begin();
        for (auto it = table.begin(); it != table.end(); ++it)
        {
            if (it->second.window_start < oldest->second.window_start)
            {
                oldest = it;
            }
        }
        table.erase(oldest);
    }

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

    [[nodiscard]] auto remaining_window_ms(TimePoint window_start, RateLimitPolicy const& policy, TimePoint now) const
        -> std::uint32_t
    {
        auto const elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - window_start).count();
        auto const window_ms = static_cast<std::int64_t>(policy.window_seconds) * 1000LL;
        auto const remaining_ms = std::max(0LL, window_ms - elapsed_ms);
        return static_cast<std::uint32_t>(remaining_ms);
    }

    [[nodiscard]] auto check_bucket(std::unordered_map<std::string, Bucket>& table, std::string_view bucket_key,
                                    std::optional<RateLimitPolicy> const& policy, TimePoint now) -> RateLimitDecision
    {
        if (!policy.has_value() || bucket_key.empty())
        {
            return RateLimitDecision{true, 0U, 0U, 0U, 0U, 0U, 0U, 0U, ""};
        }
        auto const key = std::string{bucket_key};
        auto it = table.find(key);
        if (it == table.end())
        {
            evict_to_make_room(table, now);
            it = table.emplace(key, Bucket{1U, policy->window_seconds, now}).first;
            return RateLimitDecision{true, policy->max_requests, policy->window_seconds, 1U, 1U, 0U, 0U, 0U, ""};
        }
        auto& bucket = it->second;
        bucket.window_seconds = policy->window_seconds;
        if (now - bucket.window_start >= std::chrono::seconds{policy->window_seconds})
        {
            bucket.count = 0U;
            bucket.window_start = now;
        }
        if (bucket.count >= policy->max_requests)
        {
            auto const retry_after_ms = remaining_window_ms(bucket.window_start, *policy, now);
            return RateLimitDecision{false,        policy->max_requests, policy->window_seconds,
                                     bucket.count, bucket.count,         0U,
                                     0U,           retry_after_ms,       "per_ip_cap"};
        }
        ++bucket.count;
        return RateLimitDecision{
            true, policy->max_requests, policy->window_seconds, bucket.count, bucket.count, 0U, 0U, 0U, ""};
    }

    RateLimitConfig m_config{};
    Clock* m_clock{nullptr};
    std::unordered_map<std::string, Bucket> m_ip_buckets{};
    std::unordered_map<std::string, Bucket> m_user_buckets{};
};

} // namespace merovingian::http
