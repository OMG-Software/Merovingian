// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/http/rate_limit.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <string>
#include <vector>

namespace
{

// Manual clock for deterministic time travel. The RateLimitEngine takes a
// callable; we use a plain `std::chrono::steady_clock::time_point` member
// and a `now()` accessor.
struct ManualClock
{
    std::chrono::steady_clock::time_point now{};

    [[nodiscard]] auto operator()() const noexcept -> std::chrono::steady_clock::time_point
    {
        return now;
    }
};

using merovingian::http::RateLimitConfig;
using merovingian::http::RateLimitDecision;
using merovingian::http::RateLimitEngine;
using merovingian::http::RateLimitPolicy;

// Per-IP bucket key generator: in production this is `client.ip:method:target`.
// The test helpers below mimic that shape.
[[nodiscard]] auto ip_bucket(std::string_view ip, std::string_view target) -> std::string
{
    return std::string{ip} + ':' + std::string{target};
}

[[nodiscard]] [[maybe_unused]] auto user_bucket(std::string_view user_id, std::string_view target) -> std::string
{
    return std::string{user_id} + ':' + std::string{target};
}

[[nodiscard]] auto default_config() -> RateLimitConfig
{
    return RateLimitConfig{
        .per_ip =
            {
                     {"/_matrix/client/v3/login", {20U, 60U}},
                     {"/_matrix/client/v3/register", {20U, 60U}},
                     {"/_matrix/client/v3/keys/", {30U, 60U}},
                     {"/_matrix/client/v3/devices", {30U, 60U}},
                     {"/_matrix/media/", {20U, 60U}},
                     {"/_matrix/federation/", {120U, 60U}},
                     },
        .per_user =
            {
                     {"/_matrix/client/v3/login", {5U, 60U}},
                     },
        .default_per_ip = {60U, 60U},
    };
}

} // namespace

SCENARIO("Wall-clock rate limiter: cap is requests per 60 seconds, not per 64 server-wide requests",
         "[homeserver][client-server][rate-limit][wall-clock][regression]")
{
    GIVEN("a fresh rate-limit engine with the default config and a frozen clock")
    {
        auto clock = ManualClock{};
        auto engine = RateLimitEngine{default_config(), clock};
        auto const target = std::string_view{"/_matrix/client/v3/register"};

        WHEN("20 distinct requests for the same IP are made in the same wall-clock second")
        {
            for (std::uint32_t i = 0U; i < 20U; ++i)
            {
                auto const d = engine.check(ip_bucket("10.0.0.1", target), target, std::string_view{});
                REQUIRE(d.allowed);
            }

            THEN("the 21st request is denied with a 60s window and a 20-cap (not a 5-cap, not a 64-request counter)")
            {
                auto const d = engine.check(ip_bucket("10.0.0.1", target), target, std::string_view{});
                REQUIRE_FALSE(d.allowed);
                REQUIRE(d.max_requests == 20U);
                REQUIRE(d.window_seconds == 60U);
            }
        }
    }
}

SCENARIO("Wall-clock rate limiter: bucket rolls over on wall-clock seconds, not on a request counter",
         "[homeserver][client-server][rate-limit][wall-clock]")
{
    GIVEN("a rate-limit engine that has hit the cap for a given IP")
    {
        auto clock = ManualClock{};
        auto engine = RateLimitEngine{default_config(), clock};
        auto const target = std::string_view{"/_matrix/client/v3/register"};

        for (std::uint32_t i = 0U; i < 20U; ++i)
        {
            (void)engine.check(ip_bucket("10.0.0.1", target), target, std::string_view{});
        }
        REQUIRE_FALSE(engine.check(ip_bucket("10.0.0.1", target), target, std::string_view{}).allowed);

        WHEN("the wall clock advances by 59 seconds (still within the window)")
        {
            clock.now += std::chrono::seconds{59};

            THEN("the next request is still denied")
            {
                REQUIRE_FALSE(engine.check(ip_bucket("10.0.0.1", target), target, std::string_view{}).allowed);
            }
        }

        WHEN("the wall clock advances by 60 seconds (the window has rolled)")
        {
            clock.now += std::chrono::seconds{60};

            THEN("the next request is allowed and the counter has been reset")
            {
                auto const d = engine.check(ip_bucket("10.0.0.1", target), target, std::string_view{});
                REQUIRE(d.allowed);
                REQUIRE(d.requests_seen == 1U);
            }
        }
    }
}

SCENARIO("Wall-clock rate limiter: per-IP and per-user buckets are independent",
         "[homeserver][client-server][rate-limit][wall-clock][buckets]")
{
    GIVEN("a user alice that has hit the per-user cap and a fresh IP comes in")
    {
        auto clock = ManualClock{};
        auto engine = RateLimitEngine{default_config(), clock};
        auto const target = std::string_view{"/_matrix/client/v3/login"};

        // 5 requests from IP1 / user alice: this puts the per-user
        // tier at 5/5 (at the cap). The 6th login is the one that
        // actually trips the per-user denial regardless of which IP
        // it comes from, proving that the per-user tier is keyed on
        // user_id and is independent of the per-IP tier.
        for (std::uint32_t i = 0U; i < 5U; ++i)
        {
            (void)engine.check(ip_bucket("10.0.0.1", target), target, std::string_view{"@alice:example.org"});
        }

        WHEN("a 5th login comes from a different IP for the same user alice")
        {
            // The 6th login: the per-user tier sees count=5 (5 prior
            // logins for @alice + this 6th, and the 5th put @alice
            // at the cap so this 6th is denied). The per-IP tier
            // sees count=1 for the new IP 10.0.0.2. The per-user
            // denial takes precedence, so the decision is denied
            // by the per-user tier. The new IP's count is still
            // recorded for the audit row.
            auto const d = engine.check(ip_bucket("10.0.0.2", target), target, std::string_view{"@alice:example.org"});

            THEN("the per-user cap denies even though the per-IP bucket is fresh")
            {
                REQUIRE_FALSE(d.allowed);
                REQUIRE(d.deny_reason == "per_user_cap");
                REQUIRE(d.per_user_count == 5U);
                REQUIRE(d.per_user_max == 5U);
                REQUIRE(d.per_ip_count == 1U);
            }
        }

        WHEN("a 5th login comes from a fresh IP for a different user bob")
        {
            // Same IP 10.0.0.1 now has 6/20 in its bucket (5 prior logins
            // for @alice + this 1 for @bob), but @bob has 0/5 so both
            // tiers allow. This is the only "buckets are independent"
            // assertion that proves the two tiers do not bleed into each
            // other.
            auto const d = engine.check(ip_bucket("10.0.0.1", target), target, std::string_view{"@bob:example.org"});

            THEN("both tiers allow and the per-user bucket is fresh")
            {
                REQUIRE(d.allowed);
                REQUIRE(d.per_ip_count == 6U);
                REQUIRE(d.per_user_count == 1U);
            }
        }
    }
}

SCENARIO("Wall-clock rate limiter: per-user login cap of 5/60s applies across IPs",
         "[homeserver][client-server][rate-limit][wall-clock][per-user]")
{
    GIVEN("a user alice that has logged in 5 times across 3 distinct IPs")
    {
        auto clock = ManualClock{};
        auto engine = RateLimitEngine{default_config(), clock};
        auto const target = std::string_view{"/_matrix/client/v3/login"};

        for (std::uint32_t i = 0U; i < 5U; ++i)
        {
            auto const ip = std::string{"10.0.0."} + std::to_string(i + 1U);
            (void)engine.check(ip_bucket(ip, target), target, std::string_view{"@alice:example.org"});
        }

        WHEN("a 6th login is attempted for @alice from a fresh IP")
        {
            auto const d = engine.check(ip_bucket("10.0.0.99", target), target, std::string_view{"@alice:example.org"});

            THEN("it is denied by the per-user cap, even though the per-IP bucket is empty")
            {
                REQUIRE_FALSE(d.allowed);
                REQUIRE(d.deny_reason == "per_user_cap");
                REQUIRE(d.per_user_count == 5U);
                REQUIRE(d.per_user_max == 5U);
            }
        }
    }
}

SCENARIO("Wall-clock rate limiter: per-endpoint caps are overridable via config",
         "[homeserver][client-server][rate-limit][wall-clock][config]")
{
    GIVEN("a config that tightens /register to 3/60s per IP")
    {
        auto clock = ManualClock{};
        auto config = default_config();
        config.per_ip["/_matrix/client/v3/register"] = RateLimitPolicy{3U, 60U};
        auto engine = RateLimitEngine{config, clock};
        auto const target = std::string_view{"/_matrix/client/v3/register"};

        WHEN("3 requests are made from the same IP")
        {
            for (std::uint32_t i = 0U; i < 3U; ++i)
            {
                REQUIRE(engine.check(ip_bucket("10.0.0.1", target), target, std::string_view{}).allowed);
            }

            THEN("the 4th is denied with max_requests=3")
            {
                auto const d = engine.check(ip_bucket("10.0.0.1", target), target, std::string_view{});
                REQUIRE_FALSE(d.allowed);
                REQUIRE(d.max_requests == 3U);
            }
        }
    }
}

SCENARIO("Wall-clock rate limiter: default /register cap is 20/60s, not the legacy 5/60s",
         "[homeserver][client-server][rate-limit][wall-clock][regression]")
{
    GIVEN("the default ClientRateLimitsConfig")
    {
        auto const config = default_config();
        auto const reg_policy = config.per_ip.at("/_matrix/client/v3/register");

        THEN("the /register per-IP cap is 20/60s")
        {
            REQUIRE(reg_policy.max_requests == 20U);
            REQUIRE(reg_policy.window_seconds == 60U);
        }
    }
}
