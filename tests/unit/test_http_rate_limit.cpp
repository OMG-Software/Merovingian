// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/http/rate_limit.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <functional>
#include <string>
#include <tuple>
#include <vector>

namespace
{

// Deterministic clock so policy resolution can be asserted without the
// engine consuming a bucket. The engine only reads the clock in check(),
// so the value never matters for resolve_*_policy() calls.
struct ManualClock
{
    std::chrono::steady_clock::time_point now{std::chrono::steady_clock::time_point{} + std::chrono::seconds{1}};

    [[nodiscard]] auto operator()() noexcept -> std::chrono::steady_clock::time_point
    {
        return now;
    }
};

} // namespace

SCENARIO("HTTP rate limit policy validates conservative bounds", "[http][rate-limit]")
{
    GIVEN("valid and invalid rate limit policies")
    {
        auto const default_policy = merovingian::http::RateLimitPolicy{};
        auto const zero_requests = merovingian::http::RateLimitPolicy{0U, 60U};
        auto const zero_window = merovingian::http::RateLimitPolicy{60U, 0U};
        auto const oversized_window = merovingian::http::RateLimitPolicy{60U, 3601U};

        WHEN("the policies are validated")
        {
            auto const default_valid = merovingian::http::rate_limit_policy_is_valid(default_policy);
            auto const zero_requests_valid = merovingian::http::rate_limit_policy_is_valid(zero_requests);
            auto const zero_window_valid = merovingian::http::rate_limit_policy_is_valid(zero_window);
            auto const oversized_window_valid = merovingian::http::rate_limit_policy_is_valid(oversized_window);

            THEN("only conservative bounded policies are accepted")
            {
                REQUIRE(default_valid);
                REQUIRE_FALSE(zero_requests_valid);
                REQUIRE_FALSE(zero_window_valid);
                REQUIRE_FALSE(oversized_window_valid);
            }
        }
    }
}

SCENARIO("HTTP rate limit state rejects excess requests inside a window", "[http][rate-limit]")
{
    GIVEN("a five-request policy over a sixty-second window")
    {
        auto const policy = merovingian::http::RateLimitPolicy{5U, 60U};

        WHEN("request states are evaluated")
        {
            auto const below_limit = merovingian::http::request_is_rate_limited({4U, 59U}, policy);
            auto const at_limit = merovingian::http::request_is_rate_limited({5U, 59U}, policy);
            auto const reset_window = merovingian::http::request_is_rate_limited({5U, 60U}, policy);

            THEN("only the state at the limit inside the window is rate limited")
            {
                REQUIRE_FALSE(below_limit);
                REQUIRE(at_limit);
                REQUIRE_FALSE(reset_window);
            }
        }
    }
}

SCENARIO("HTTP endpoint defaults protect sensitive Matrix endpoints", "[http][rate-limit]")
{
    GIVEN("Matrix endpoint methods and paths")
    {
        auto constexpr post = "POST";
        auto constexpr get = "GET";
        auto constexpr put = "PUT";

        WHEN("default endpoint rate limits are selected")
        {
            auto const login = merovingian::http::endpoint_default_rate_limit(post, "/_matrix/client/v3/login");
            auto const keys = merovingian::http::endpoint_default_rate_limit(post, "/_matrix/client/v3/keys/upload");
            auto const media = merovingian::http::endpoint_default_rate_limit(get, "/_matrix/media/v3/download/a/b");
            auto const media_v1 =
                merovingian::http::endpoint_default_rate_limit(get, "/_matrix/client/v1/media/download/a/b");
            auto const federation =
                merovingian::http::endpoint_default_rate_limit(put, "/_matrix/federation/v1/send/1");
            auto const generic = merovingian::http::endpoint_default_rate_limit(get, "/_matrix/client/v3/sync");

            THEN("the new route-aware burst defaults apply while login remains tight")
            {
                REQUIRE(login.max_requests == 20U);
                REQUIRE(keys.max_requests == 120U);
                REQUIRE(media.max_requests == 120U);
                REQUIRE(media_v1.max_requests == 120U);
                REQUIRE(federation.max_requests == 3000U);
                REQUIRE(generic.max_requests == 3000U);
            }
        }
    }
}

SCENARIO("HTTP default client rate limit config resolves the design-doc caps per route", "[http][rate-limit]")
{
    GIVEN("an engine built from the default client rate limit configuration")
    {
        auto clock = ManualClock{};
        auto const cfg = merovingian::http::default_client_rate_limit_config();
        auto const engine = merovingian::http::RateLimitEngine{cfg, clock};

        WHEN("per-IP policies are resolved for representative routes")
        {
            auto const login = engine.resolve_per_ip_policy("/_matrix/client/v3/login");
            auto const reg = engine.resolve_per_ip_policy("/_matrix/client/v3/register");
            auto const refresh = engine.resolve_per_ip_policy("/_matrix/client/v3/refresh");
            auto const request_token =
                engine.resolve_per_ip_policy("/_matrix/client/v3/account/3pid/email/requestToken");
            auto const keys = engine.resolve_per_ip_policy("/_matrix/client/v3/keys/upload");
            auto const devices = engine.resolve_per_ip_policy("/_matrix/client/v3/devices");
            auto const search = engine.resolve_per_ip_policy("/_matrix/client/v3/search");
            auto const media = engine.resolve_per_ip_policy("/_matrix/media/v3/download/a/b");
            auto const media_v1 = engine.resolve_per_ip_policy("/_matrix/client/v1/media/download/a/b");
            auto const sync = engine.resolve_per_ip_policy("/_matrix/client/v3/sync");
            auto const federation = engine.resolve_per_ip_policy("/_matrix/federation/v1/query/profile");
            auto const admin = engine.resolve_per_ip_policy("/_merovingian/admin/stats");
            auto const generic = engine.resolve_per_ip_policy("/_matrix/client/v3/account/whoami");
            auto const user_login = engine.resolve_per_user_policy("/_matrix/client/v3/login");

            THEN("the configured defaults apply and login remains per-user limited")
            {
                REQUIRE(login.has_value());
                REQUIRE(login->max_requests == 20U);
                REQUIRE(reg.has_value());
                REQUIRE(reg->max_requests == 20U);
                REQUIRE(refresh.has_value());
                REQUIRE(refresh->max_requests == 20U);
                REQUIRE(request_token.has_value());
                REQUIRE(request_token->max_requests == 20U);
                REQUIRE(keys.has_value());
                REQUIRE(keys->max_requests == 120U);
                REQUIRE(devices.has_value());
                REQUIRE(devices->max_requests == 120U);
                REQUIRE(search.has_value());
                REQUIRE(search->max_requests == 20U);
                REQUIRE(media.has_value());
                REQUIRE(media->max_requests == 120U);
                REQUIRE(media_v1.has_value());
                REQUIRE(media_v1->max_requests == 120U);
                REQUIRE(sync.has_value());
                REQUIRE(sync->max_requests == 3000U);
                REQUIRE(federation.has_value());
                REQUIRE(federation->max_requests == 3000U);
                REQUIRE(admin.has_value());
                REQUIRE(admin->max_requests == 30U);
                REQUIRE(generic.has_value());
                REQUIRE(generic->max_requests == 600U);
                REQUIRE(user_login.has_value());
                REQUIRE(user_login->max_requests == 5U);
            }
        }
    }
}

SCENARIO("HTTP rate limit summary is stable", "[http][rate-limit]")
{
    GIVEN("a rate limit policy")
    {
        auto const policy = merovingian::http::RateLimitPolicy{5U, 60U};

        WHEN("the rate limit summary is generated")
        {
            auto const summary = merovingian::http::rate_limit_summary(policy);

            THEN("the expected fields are present")
            {
                REQUIRE(summary.find("max_requests=5") != std::string::npos);
                REQUIRE(summary.find("window_seconds=60") != std::string::npos);
            }
        }
    }
}

// M-02 (security audit 2026-09). The rate limiter's per-IP and per-user bucket
// tables are keyed by strings an attacker influences (`client_ip|target`, and a
// user ID). `std::hash<std::string>` is not collision-resistant and is not
// randomised per process, so one precomputed set of colliding keys degrades the
// table into a linear scan on every deployment — turning the structure that
// defends against floods into the target of one.
SCENARIO("Rate limit bucket keys are hashed with a keyed, collision-resistant hash", "[http][rate-limit][security]")
{
    GIVEN("the bucket-key hasher and a sample of realistic bucket keys")
    {
        auto const hasher = merovingian::http::BucketKeyHash{};
        auto const keys = std::vector<std::string>{
            "203.0.113.7|/_matrix/client/v3/login",
            "203.0.113.7|/_matrix/client/v3/register",
            "198.51.100.4|/_matrix/client/v3/login",
            "@alice:example.org",
            "@bob:example.org",
            "2001:db8::1|/_matrix/client/v3/sync",
        };

        WHEN("each key is hashed")
        {
            auto digests = std::vector<std::size_t>{};
            for (auto const& key : keys)
            {
                digests.push_back(hasher(key));
            }

            THEN("no digest matches what the default std::hash would have produced")
            {
                // Not a cryptographic claim about std::hash — just proof that
                // the default implementation is no longer the one in use.
                for (auto index = std::size_t{0U}; index < keys.size(); ++index)
                {
                    REQUIRE(digests[index] != std::hash<std::string>{}(keys[index]));
                }
            }

            THEN("distinct keys produce distinct digests")
            {
                auto sorted = digests;
                std::ranges::sort(sorted);
                REQUIRE(std::ranges::adjacent_find(sorted) == sorted.end());
            }

            THEN("the same key hashes the same way within one process")
            {
                for (auto index = std::size_t{0U}; index < keys.size(); ++index)
                {
                    REQUIRE(hasher(keys[index]) == digests[index]);
                }
            }
        }
    }
}

SCENARIO("Rate limiting still enforces its cap under a flood of distinct bucket keys", "[http][rate-limit][security]")
{
    GIVEN("an engine that has been filled with many distinct per-IP keys")
    {
        auto clock = ManualClock{};
        auto const cfg = merovingian::http::default_client_rate_limit_config();
        auto engine = merovingian::http::RateLimitEngine{cfg, clock};

        for (auto index = 0U; index < 5000U; ++index)
        {
            std::ignore = engine.check("198.51.100.1|" + std::to_string(index), "/_matrix/client/v3/sync", {});
        }

        WHEN("one victim key then exceeds its own cap")
        {
            auto rejected = false;
            for (auto attempt = 0U; attempt < 5000U && !rejected; ++attempt)
            {
                rejected = !engine.check("203.0.113.99", "/_matrix/client/v3/sync", {}).allowed;
            }

            THEN("the cap is still enforced and the table stays bounded")
            {
                REQUIRE(rejected);
                REQUIRE(engine.ip_bucket_count() <= 100000U);
            }
        }
    }
}
