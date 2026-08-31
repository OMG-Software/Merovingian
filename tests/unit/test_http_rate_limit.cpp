// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/http/rate_limit.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <string>

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

            THEN("sensitive endpoints receive stricter limits")
            {
                REQUIRE(login.max_requests == 20U);
                REQUIRE(keys.max_requests == 30U);
                REQUIRE(media.max_requests == 20U);
                REQUIRE(media_v1.max_requests == 20U);
                REQUIRE(federation.max_requests == 120U);
                REQUIRE(generic.max_requests == 90U);
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

            THEN("the design-doc caps apply")
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
                REQUIRE(keys->max_requests == 30U);
                REQUIRE(devices.has_value());
                REQUIRE(devices->max_requests == 30U);
                REQUIRE(search.has_value());
                REQUIRE(search->max_requests == 20U);
                REQUIRE(media.has_value());
                REQUIRE(media->max_requests == 20U);
                REQUIRE(media_v1.has_value());
                REQUIRE(media_v1->max_requests == 20U);
                REQUIRE(sync.has_value());
                REQUIRE(sync->max_requests == 90U);
                REQUIRE(federation.has_value());
                REQUIRE(federation->max_requests == 120U);
                REQUIRE(admin.has_value());
                REQUIRE(admin->max_requests == 30U);
                REQUIRE(generic.has_value());
                REQUIRE(generic->max_requests == 90U);
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
