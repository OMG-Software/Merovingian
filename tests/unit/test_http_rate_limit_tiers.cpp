// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/http/rate_limit.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <string>

namespace
{

// Deterministic clock: the engine only reads the clock in check(), so a
// frozen value is enough for both policy resolution and cap scenarios.
struct ManualClock
{
    std::chrono::steady_clock::time_point now{std::chrono::steady_clock::time_point{} + std::chrono::seconds{1}};

    [[nodiscard]] auto operator()() noexcept -> std::chrono::steady_clock::time_point
    {
        return now;
    }
};

using merovingian::http::RateLimitConfig;
using merovingian::http::RateLimitEngine;
using merovingian::http::RateLimitPolicy;
using merovingian::http::RateLimitTier;

[[nodiscard]] auto tier_of(std::string_view target) -> RateLimitTier
{
    return merovingian::http::rate_limit_tier_for(target);
}

[[nodiscard]] auto resolved_max(RateLimitEngine<ManualClock> const& engine, std::string_view target) -> std::uint32_t
{
    auto const policy = engine.resolve_per_ip_policy(target);
    REQUIRE(policy.has_value());
    return policy->max_requests;
}

} // namespace

SCENARIO("Rate-limit tiers classify client-server routes explicitly", "[http][rate-limit][tier]")
{
    GIVEN("the greppable classification table in rate_limit_tier_for()")
    {
        WHEN("representative routes are classified")
        {
            THEN("each route lands in the tier that matches its abuse surface")
            {
                // auth_sensitive: unauthenticated credential/enumeration routes.
                REQUIRE(tier_of("/_matrix/client/v3/login") == RateLimitTier::auth_sensitive);
                REQUIRE(tier_of("/_matrix/client/v3/refresh") == RateLimitTier::auth_sensitive);
                REQUIRE(tier_of("/_matrix/client/v3/register") == RateLimitTier::auth_sensitive);
                REQUIRE(tier_of("/_matrix/client/v3/account/3pid/email/requestToken") == RateLimitTier::auth_sensitive);
                REQUIRE(tier_of("/_matrix/client/v3/account/3pid/msisdn/requestToken") ==
                        RateLimitTier::auth_sensitive);
                REQUIRE(tier_of("/_matrix/client/v3/register/email/requestToken") == RateLimitTier::auth_sensitive);
                // Method-agnostic: a GET against /login is the same surface.
                REQUIRE(tier_of("/_matrix/client/v3/login/sso/redirect") == RateLimitTier::auth_sensitive);

                // media: both media trees.
                REQUIRE(tier_of("/_matrix/media/v3/download/a/b") == RateLimitTier::media);
                REQUIRE(tier_of("/_matrix/media/v3/thumbnail/a/b?width=1") == RateLimitTier::media);
                REQUIRE(tier_of("/_matrix/client/v1/media/download/a/b") == RateLimitTier::media);
                REQUIRE(tier_of("/_matrix/client/v1/media/upload?filename=x") == RateLimitTier::media);

                // sync: the three long-poll surfaces.
                REQUIRE(tier_of("/_matrix/client/v3/sync?timeout=30000") == RateLimitTier::sync);
                REQUIRE(tier_of("/_matrix/client/unstable/org.matrix.msc4186/sync") == RateLimitTier::sync);
                REQUIRE(tier_of("/_matrix/client/unstable/org.matrix.simplified_msc3575/sync") == RateLimitTier::sync);

                // federation: routes reaching the client-server dispatcher.
                REQUIRE(tier_of("/_matrix/federation/v1/query/profile") == RateLimitTier::federation);
                REQUIRE(tier_of("/_matrix/federation/v1/backfill/!room/x") == RateLimitTier::federation);

                // admin: the operator surface.
                REQUIRE(tier_of("/_merovingian/admin/health") == RateLimitTier::admin);

                // generic: everything else.
                REQUIRE(tier_of("/_matrix/client/v3/account/whoami") == RateLimitTier::generic);
                REQUIRE(tier_of("/_matrix/client/v3/rooms/!room/send/m.room.message") == RateLimitTier::generic);
            }
        }
    }
}

SCENARIO("Rate-limit tier names round-trip with the config parser's vocabulary", "[http][rate-limit][tier]")
{
    GIVEN("the six tier names accepted by client_rate_limits.tier.<name>")
    {
        auto const names = {
            "auth_sensitive", "media", "sync", "federation", "admin", "generic",
        };

        WHEN("each name is resolved to a tier and back")
        {
            THEN("rate_limit_tier_name and rate_limit_tier_from_name are inverses")
            {
                for (auto const* name : names)
                {
                    auto const tier = merovingian::http::rate_limit_tier_from_name(name);
                    REQUIRE(tier.has_value());
                    REQUIRE(merovingian::http::rate_limit_tier_name(*tier) == name);
                }
            }
        }

        WHEN("a misspelled or unknown tier name is resolved")
        {
            THEN("it resolves to nullopt so the config parser can reject it as a finding")
            {
                REQUIRE_FALSE(merovingian::http::rate_limit_tier_from_name("login").has_value());
                REQUIRE_FALSE(merovingian::http::rate_limit_tier_from_name("AUTH_SENSITIVE").has_value());
                REQUIRE_FALSE(merovingian::http::rate_limit_tier_from_name("").has_value());
                REQUIRE_FALSE(merovingian::http::rate_limit_tier_from_name("generic ").has_value());
            }
        }
    }
}

SCENARIO("Rate-limit tier defaults carry the secure design-doc caps", "[http][rate-limit][tier]")
{
    GIVEN("the tier default table in rate_limit_tier_default()")
    {
        WHEN("each tier's default policy is read")
        {
            auto const auth_sensitive = merovingian::http::rate_limit_tier_default(RateLimitTier::auth_sensitive);
            auto const media = merovingian::http::rate_limit_tier_default(RateLimitTier::media);
            auto const sync = merovingian::http::rate_limit_tier_default(RateLimitTier::sync);
            auto const federation = merovingian::http::rate_limit_tier_default(RateLimitTier::federation);
            auto const admin = merovingian::http::rate_limit_tier_default(RateLimitTier::admin);
            auto const generic = merovingian::http::rate_limit_tier_default(RateLimitTier::generic);

            THEN("unauthenticated and expensive surfaces are tighter than the generic fallback")
            {
                REQUIRE(auth_sensitive == RateLimitPolicy{20U, 60U});
                REQUIRE(media == RateLimitPolicy{20U, 60U});
                REQUIRE(sync == RateLimitPolicy{90U, 60U});
                REQUIRE(federation == RateLimitPolicy{120U, 60U});
                REQUIRE(admin == RateLimitPolicy{30U, 60U});
                REQUIRE(generic == RateLimitPolicy{90U, 60U});
            }
        }
    }
}

SCENARIO("Rate-limit tier overrides apply to every route in the tier", "[http][rate-limit][tier][config]")
{
    GIVEN("an engine whose operator tightened the media tier and the auth_sensitive tier")
    {
        auto clock = ManualClock{};
        auto config = merovingian::http::default_client_rate_limit_config();
        config.tier["media"] = RateLimitPolicy{5U, 60U};
        config.tier["auth_sensitive"] = RateLimitPolicy{2U, 60U};
        auto const engine = RateLimitEngine{config, clock};

        WHEN("policies are resolved for several routes in each overridden tier")
        {
            THEN("every route in the tier sees the override")
            {
                REQUIRE(resolved_max(engine, "/_matrix/media/v3/download/a/b") == 5U);
                REQUIRE(resolved_max(engine, "/_matrix/client/v1/media/thumbnail/a/b") == 5U);
                REQUIRE(resolved_max(engine, "/_matrix/client/v3/login") == 2U);
                REQUIRE(resolved_max(engine, "/_matrix/client/v3/account/3pid/email/requestToken") == 2U);
            }
            AND_THEN("routes in other tiers keep their own defaults")
            {
                REQUIRE(resolved_max(engine, "/_matrix/client/v3/account/whoami") == 90U);
                REQUIRE(resolved_max(engine, "/_matrix/client/v3/sync") == 90U);
            }
        }
    }
}

SCENARIO("Rate-limit policy resolution honours most-specific-first precedence", "[http][rate-limit][tier][config]")
{
    GIVEN("a config with an operator per-prefix entry, a tier override and a built-in refinement in play")
    {
        auto clock = ManualClock{};
        auto config = merovingian::http::default_client_rate_limit_config();
        // Tier override for the generic tier (which contains the keys routes).
        config.tier["generic"] = RateLimitPolicy{7U, 60U};
        auto const engine = RateLimitEngine{config, clock};

        WHEN("a keys route is resolved with only a tier override present")
        {
            THEN("the tier override beats the built-in 30/60s refinement")
            {
                REQUIRE(resolved_max(engine, "/_matrix/client/v3/keys/upload") == 7U);
                REQUIRE(resolved_max(engine, "/_matrix/client/v3/devices") == 7U);
            }
        }

        WHEN("an operator per-prefix entry for the same route is added")
        {
            auto config2 = config;
            config2.per_ip["/_matrix/client/v3/keys/upload"] = RateLimitPolicy{3U, 60U};
            auto const engine2 = RateLimitEngine{config2, clock};

            THEN("the operator per-prefix entry beats the tier override")
            {
                REQUIRE(resolved_max(engine2, "/_matrix/client/v3/keys/upload") == 3U);
                // Longest prefix wins: the upload entry does not shadow query.
                REQUIRE(resolved_max(engine2, "/_matrix/client/v3/keys/query") == 7U);
            }
        }

        WHEN("the generic tier is left at the operator-tunable default_per_ip")
        {
            auto config3 = config;
            config3.tier.erase("generic");
            config3.default_per_ip = RateLimitPolicy{42U, 60U};
            auto const engine3 = RateLimitEngine{config3, clock};

            THEN("generic routes resolve to default_per_ip while built-in refinements still win inside the tier")
            {
                REQUIRE(resolved_max(engine3, "/_matrix/client/v3/account/whoami") == 42U);
                REQUIRE(resolved_max(engine3, "/_matrix/client/v3/keys/upload") == 30U);
            }
        }
    }
}

SCENARIO("Rate-limit tier overrides fail closed when misconfigured", "[http][rate-limit][tier][security]")
{
    GIVEN("an engine whose operator tier override is out of range")
    {
        auto clock = ManualClock{};
        auto config = merovingian::http::default_client_rate_limit_config();
        config.tier["auth_sensitive"] = RateLimitPolicy{20U, 3601U}; // window beyond the 3600s bound
        // check() mutates the bucket table, so this engine cannot be const.
        auto engine = RateLimitEngine{config, clock};

        WHEN("a request is checked against the invalid override")
        {
            auto const decision = engine.check("10.0.0.1|/_matrix/client/v3/login", "/_matrix/client/v3/login", "");

            THEN("the request is denied rather than silently unlimited")
            {
                REQUIRE_FALSE(decision.allowed);
                REQUIRE(decision.deny_reason == "invalid_policy");
            }
        }
    }
}

SCENARIO("Unauthenticated auth-sensitive routes get the tight tier cap, not the generic fallback",
         "[http][rate-limit][tier][regression]")
{
    GIVEN("an engine built from the default config")
    {
        auto clock = ManualClock{};
        // check() mutates the bucket table, so this engine cannot be const.
        auto engine = RateLimitEngine{merovingian::http::default_client_rate_limit_config(), clock};
        auto const target = std::string_view{"/_matrix/client/v3/account/3pid/email/requestToken"};

        WHEN("an IP drives 20 requests at the unauthenticated requestToken route")
        {
            auto decisions = std::vector<bool>{};
            for (auto i = 0U; i < 21U; ++i)
            {
                decisions.push_back(engine.check("203.0.113.9|" + std::string{target}, target, "").allowed);
            }

            THEN("the first 20 are allowed and the 21st is denied by the auth_sensitive cap")
            {
                for (auto i = 0U; i < 20U; ++i)
                {
                    REQUIRE(decisions.at(i));
                }
                REQUIRE_FALSE(decisions.at(20U));
            }
        }
    }
}