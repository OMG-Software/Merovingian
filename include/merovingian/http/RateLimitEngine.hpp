// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/http/BucketKeyHash.hpp"
#include "merovingian/http/RateLimitConfig.hpp"
#include "merovingian/http/RateLimitDecision.hpp"
#include "merovingian/http/RateLimitPolicy.hpp"
#include "merovingian/http/RateLimitTier.hpp"
#include "merovingian/http/rate_limit.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <list>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>

namespace merovingian::http
{

// The engine. Templated on the clock so tests can supply a
// std::chrono::steady_clock::time_point-producing callable. In
// production the clock is a thin wrapper over std::chrono::steady_clock.
template <typename Clock, std::size_t MaxBuckets = 100'000U>
class RateLimitEngine final
{
public:
    static_assert(MaxBuckets > 0U);
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

    RateLimitEngine(RateLimitEngine const&) = delete;
    auto operator=(RateLimitEngine const&) -> RateLimitEngine& = delete;
    RateLimitEngine(RateLimitEngine&&) = delete;
    auto operator=(RateLimitEngine&&) -> RateLimitEngine& = delete;

    // Per-IP policy resolution, most specific first:
    //   1. operator `per_ip` entry (longest target-prefix match),
    //   2. operator `tier` override for the route's tier,
    //   3. built-in per-endpoint refinement (`builtin_per_ip`),
    //   4. the tier default (`rate_limit_tier_default()`); the generic tier
    //      resolves to the operator-tunable `default_per_ip`.
    // An invalid policy at whichever level matched resolves to std::nullopt
    // so check() can fail closed (issue #412) — a misconfigured entry must
    // never be treated as "no limit".
    [[nodiscard]] auto resolve_per_ip_policy(std::string_view target, std::string_view policy_target = {}) const
        -> std::optional<RateLimitPolicy>
    {
        auto const* operator_prefix = lookup_policy(m_config.per_ip, target, policy_target);
        if (operator_prefix != nullptr)
        {
            return valid_or_nullopt(*operator_prefix);
        }
        auto const tier = rate_limit_tier_for(policy_target.empty() ? target : policy_target);
        auto const tier_name = rate_limit_tier_name(tier);
        if (auto const it = m_config.tier.find(std::string{tier_name}); it != m_config.tier.end())
        {
            return valid_or_nullopt(it->second);
        }
        // Built-in refinements are prefixes of real paths, so they must also
        // see the original path: a route that normalizes to the shared
        // fallback would otherwise lose its refinement.
        if (auto const* refinement = lookup_policy(m_config.builtin_per_ip, target, policy_target);
            refinement != nullptr)
        {
            return valid_or_nullopt(*refinement);
        }
        if (tier == RateLimitTier::generic)
        {
            return valid_or_nullopt(m_config.default_per_ip);
        }
        return rate_limit_tier_default(tier);
    }

    // Per-user policy resolution: operator `per_user` entry first, then the
    // built-in per-user login cap. Unlisted routes resolve to std::nullopt
    // and the per-user tier is skipped for them.
    [[nodiscard]] auto resolve_per_user_policy(std::string_view target, std::string_view policy_target = {}) const
        -> std::optional<RateLimitPolicy>
    {
        auto const* policy = lookup_policy(m_config.per_user, target, policy_target);
        if (policy == nullptr)
        {
            policy = lookup_policy(m_config.builtin_per_user, target, policy_target);
        }
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
    auto check(std::string_view ip_bucket, std::string_view target, std::string_view user_bucket,
               std::string_view policy_target = {}) -> RateLimitDecision
    {
        auto const now = (*m_clock)();
        auto const per_ip = resolve_per_ip_policy(target, policy_target);
        auto const per_user = resolve_per_user_policy(target, policy_target);

        if (!per_ip.has_value())
        {
            // Fail closed: the per-IP policy is the base limit on every route
            // and only resolves to nullopt when a configured entry, tier
            // override or the default fails rate_limit_policy_is_valid()
            // (issue #412). An unresolvable per-IP policy must never be
            // treated as "no limit" — deny even when a valid per-user policy
            // exists, because the per-IP bucket is the only defense on
            // unauthenticated routes. (A nullopt per-user policy is the
            // normal state for routes with no per-user cap and is fine.)
            return RateLimitDecision{.allowed = false, .deny_reason = "invalid_policy"};
        }

        auto const ip_decision = ip_bucket.empty() ? RateLimitDecision{true, 0U, 0U, 0U, 0U, 0U, 0U, 0U, ""}
                                                   : check_bucket(m_ip_buckets, ip_bucket, m_ip_lru, per_ip, now);
        auto const user_decision = user_bucket.empty()
                                       ? RateLimitDecision{true, 0U, 0U, 0U, 0U, 0U, 0U, 0U, ""}
                                       : check_bucket(m_user_buckets, user_bucket, m_user_lru, per_user, now);

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
        m_ip_lru.clear();
        m_user_lru.clear();
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
    using LruList = std::list<std::string>;

    struct Bucket final
    {
        std::uint32_t count{0U};
        // The window length in force when this bucket was created/reset.
        // Stored per-bucket because entries in the same table can belong to
        // different routes with different configured windows.
        std::uint32_t window_seconds{0U};
        TimePoint window_start{};
        LruList::iterator recency{};
    };

    using BucketTable = std::unordered_map<std::string, Bucket, BucketKeyHash>;

    // Bounds each bucket table so an attacker who can force many distinct keys
    // (e.g. rotating a client-supplied X-Forwarded-For value through a trusted
    // proxy) cannot grow memory or per-check scan cost without bound. Set well
    // above any plausible legitimate concurrent-key count. An O(1) LRU entry
    // is evicted only when a new key arrives at capacity.
    static constexpr std::size_t kMaxBucketsPerTable = MaxBuckets;

    // Makes room in `table` for a new key by evicting the least-recently-used
    // bucket. List splice and the corresponding map erase keep admission cost
    // constant even when an attacker supplies a fresh key on every request.
    static auto evict_to_make_room(BucketTable& table, LruList& lru) -> void
    {
        if (table.size() >= kMaxBucketsPerTable)
        {
            table.erase(lru.front());
            lru.pop_front();
        }
    }

    // Shared fail-closed shim for policy resolution: an entry that fails
    // rate_limit_policy_is_valid() resolves to std::nullopt so check() can
    // reject rather than silently proceed (issue #412).
    [[nodiscard]] static auto valid_or_nullopt(RateLimitPolicy const& policy) -> std::optional<RateLimitPolicy>
    {
        if (!rate_limit_policy_is_valid(policy))
        {
            return std::nullopt;
        }
        return policy;
    }

    [[nodiscard]] static auto lookup_policy(std::unordered_map<std::string, RateLimitPolicy> const& table,
                                            std::string_view target, std::string_view policy_target = {})
        -> RateLimitPolicy const*
    {
        // Match both the normalized template and original path. The former
        // allows route-wide configuration; the latter preserves existing
        // operator prefixes for paths that normalize to the shared fallback.
        auto best = static_cast<RateLimitPolicy const*>(nullptr);
        auto best_len = std::size_t{0U};
        for (auto const& [key, policy] : table)
        {
            auto const matches = [&](std::string_view candidate) {
                return candidate.size() >= key.size() && candidate.substr(0U, key.size()) == key;
            };
            if ((matches(target) || matches(policy_target)) && key.size() > best_len)
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

    [[nodiscard]] auto check_bucket(BucketTable& table, std::string_view bucket_key, LruList& lru,
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
            evict_to_make_room(table, lru);
            lru.push_back(key);
            auto const recency = std::prev(lru.end());
            try
            {
                it = table.emplace(key, Bucket{1U, policy->window_seconds, now, recency}).first;
            }
            catch (...)
            {
                lru.erase(recency);
                throw;
            }
            return RateLimitDecision{true, policy->max_requests, policy->window_seconds, 1U, 1U, 0U, 0U, 0U, ""};
        }
        auto& bucket = it->second;
        lru.splice(lru.end(), lru, bucket.recency);
        bucket.recency = std::prev(lru.end());
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
    BucketTable m_ip_buckets{};
    BucketTable m_user_buckets{};
    LruList m_ip_lru{};
    LruList m_user_lru{};
};

} // namespace merovingian::http
