// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/http/rate_limit.hpp>

#include <catch2/catch_test_macros.hpp>

#include <string>

TEST_CASE("HTTP rate limit policy validates conservative bounds", "[http][rate-limit]")
{
    REQUIRE(merovingian::http::rate_limit_policy_is_valid(merovingian::http::RateLimitPolicy{}));
    REQUIRE_FALSE(merovingian::http::rate_limit_policy_is_valid({0U, 60U}));
    REQUIRE_FALSE(merovingian::http::rate_limit_policy_is_valid({60U, 0U}));
    REQUIRE_FALSE(merovingian::http::rate_limit_policy_is_valid({60U, 3601U}));
}

TEST_CASE("HTTP rate limit state rejects excess requests inside a window", "[http][rate-limit]")
{
    auto const policy = merovingian::http::RateLimitPolicy{5U, 60U};

    REQUIRE_FALSE(merovingian::http::request_is_rate_limited({4U, 59U}, policy));
    REQUIRE(merovingian::http::request_is_rate_limited({5U, 59U}, policy));
    REQUIRE_FALSE(merovingian::http::request_is_rate_limited({5U, 60U}, policy));
}

TEST_CASE("HTTP endpoint defaults protect sensitive Matrix endpoints", "[http][rate-limit]")
{
    auto const login = merovingian::http::endpoint_default_rate_limit("POST", "/_matrix/client/v3/login");
    auto const keys = merovingian::http::endpoint_default_rate_limit("POST", "/_matrix/client/v3/keys/upload");
    auto const media = merovingian::http::endpoint_default_rate_limit("GET", "/_matrix/media/v3/download/a/b");
    auto const federation = merovingian::http::endpoint_default_rate_limit("PUT", "/_matrix/federation/v1/send/1");
    auto const generic = merovingian::http::endpoint_default_rate_limit("GET", "/_matrix/client/v3/sync");

    REQUIRE(login.max_requests == 5U);
    REQUIRE(keys.max_requests == 30U);
    REQUIRE(media.max_requests == 20U);
    REQUIRE(federation.max_requests == 120U);
    REQUIRE(generic.max_requests == 60U);
}

TEST_CASE("HTTP rate limit summary is stable", "[http][rate-limit]")
{
    auto const summary = merovingian::http::rate_limit_summary({5U, 60U});

    REQUIRE(summary.find("max_requests=5") != std::string::npos);
    REQUIRE(summary.find("window_seconds=60") != std::string::npos);
}
