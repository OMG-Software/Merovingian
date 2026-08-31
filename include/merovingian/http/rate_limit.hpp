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

// Explicit client-server route tiers. The classification lives in
// rate_limit_tier_for() (src/http/rate_limit.cpp) as one greppable prefix
// table, and each tier's default policy lives in rate_limit_tier_default().
// Operators override a whole tier via `client_rate_limits.tier.<name>`
// config keys (auth_sensitive, media, sync, federation, admin, generic).
enum class RateLimitTier // no `final`: clang <= 18 rejects `final` on enums (C++26)
{
    // Unauthenticated credential/enumeration surface: /login, /register,
    // /refresh and every */requestToken route. These have no authenticated
    // user to key on, so the per-IP bucket is the only defense and the tier
    // default is tighter than the generic fallback.
    auth_sensitive,
    // Media download/thumbnail/upload, both the legacy /_matrix/media/ tree
    // and the authenticated /_matrix/client/v1/media/ tree.
    media,
    // /sync and the MSC4186 / simplified MSC3575 sliding-sync long-polls.
    sync,
    // /_matrix/federation/* routes reaching the client-server dispatcher.
    // Inbound federation on the federation listener is limited per verified
    // origin server name instead (see security.federation.per_origin_*).
    federation,
    // /_merovingian/admin/* operator surface.
    admin,
    // Every other client-server route.
    generic,
};

[[nodiscard]] auto rate_limit_tier_for(std::string_view target) noexcept -> RateLimitTier;
[[nodiscard]] auto rate_limit_tier_name(RateLimitTier tier) noexcept -> std::string_view;
// Inverse of rate_limit_tier_name(); std::nullopt for an unknown tier name.
// Used by the config parser so a typo in client_rate_limits.tier.<name>
// becomes a parse finding instead of a silently ignored key.
[[nodiscard]] auto rate_limit_tier_from_name(std::string_view name) noexcept -> std::optional<RateLimitTier>;
[[nodiscard]] auto rate_limit_tier_default(RateLimitTier tier) noexcept -> RateLimitPolicy;

[[nodiscard]] auto rate_limit_policy_is_valid(RateLimitPolicy const& policy) noexcept -> bool;
[[nodiscard]] auto request_is_rate_limited(RateLimitState state, RateLimitPolicy policy) -> bool;
[[nodiscard]] auto endpoint_default_rate_limit(std::string_view method, std::string_view target) noexcept
    -> RateLimitPolicy;
[[nodiscard]] auto rate_limit_summary(RateLimitPolicy const& policy) -> std::string;

struct RateLimitConfig final
{
    // Built-in per-endpoint refinements WITHIN a tier, seeded by
    // `default_client_rate_limit_config()` (keys/devices at 30/60s, search at
    // 20/60s) plus the built-in per-user login cap. These are the secure
    // defaults; operators do not write them directly.
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

    // Per-IP policy resolution, most specific first:
    //   1. operator `per_ip` entry (longest target-prefix match),
    //   2. operator `tier` override for the route's tier,
    //   3. built-in per-endpoint refinement (`builtin_per_ip`),
    //   4. the tier default (`rate_limit_tier_default()`); the generic tier
    //      resolves to the operator-tunable `default_per_ip`.
    // An invalid policy at whichever level matched resolves to std::nullopt
    // so check() can fail closed (issue #412) — a misconfigured entry must
    // never be treated as "no limit".
    [[nodiscard]] auto resolve_per_ip_policy(std::string_view target) const -> std::optional<RateLimitPolicy>
    {
        auto const* operator_prefix = lookup_policy(m_config.per_ip, target);
        if (operator_prefix != nullptr)
        {
            return valid_or_nullopt(*operator_prefix);
        }
        auto const tier = rate_limit_tier_for(target);
        auto const tier_name = rate_limit_tier_name(tier);
        if (auto const it = m_config.tier.find(std::string{tier_name}); it != m_config.tier.end())
        {
            return valid_or_nullopt(it->second);
        }
        if (auto const* refinement = lookup_policy(m_config.builtin_per_ip, target); refinement != nullptr)
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
    [[nodiscard]] auto resolve_per_user_policy(std::string_view target) const -> std::optional<RateLimitPolicy>
    {
        auto const* policy = lookup_policy(m_config.per_user, target);
        if (policy == nullptr)
        {
            policy = lookup_policy(m_config.builtin_per_user, target);
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
    auto check(std::string_view ip_bucket, std::string_view target, std::string_view user_bucket) -> RateLimitDecision
    {
        auto const now = (*m_clock)();
        auto const per_ip = resolve_per_ip_policy(target);
        auto const per_user = resolve_per_user_policy(target);

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
