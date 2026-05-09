// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/http/rate_limit.hpp>

#include <catch2/catch_test_macros.hpp>

#include <string>

TEST_CASE("HTTP rate limit policy validates conservative bounds", "[http][rate-limit]")
{
    // Given
    auto const default_policy = merovingian::http::RateLimitPolicy{};
    auto const zero_requests = merovingian::http::RateLimitPolicy{0U, 60U};
    auto const zero_window = merovingian::http::RateLimitPolicy{60U, 0U};
    auto const oversized_window = merovingian::http::RateLimitPolicy{60U, 3601U};

    // When
    auto const default_valid = merovingian::http::rate_limit_policy_is_valid(default_policy);
    auto const zero_requests_valid = merovingian::http::rate_limit_policy_is_valid(zero_requests);
    auto const zero_window_valid = merovingian::http::rate_limit_policy_is_valid(zero_window);
    auto const oversized_window_valid = merovingian::http::rate_limit_policy_is_valid(oversized_window);

    // Then
    REQUIRE(default_valid);
    REQUIRE_FALSE(zero_requests_valid);
    REQUIRE_FALSE(zero_window_valid);
    REQUIRE_FALSE(oversized_window_valid);
}

TEST_CASE("HTTP rate limit state rejects excess requests inside a window", "[http][rate-limit]")
{
    // Given
    auto const policy = merovingian::http::RateLimitPolicy{5U, 60U};

    // When
    auto const below_limit = merovingian::http::request_is_rate_limited({4U, 59U}, policy);
    auto const at_limit = merovingian::http::request_is_rate_limited({5U, 59U}, policy);
    auto const reset_window = merovingian::http::request_is_rate_limited({5U, 60U}, policy);

    // Then
    REQUIRE_FALSE(below_limit);
    REQUIRE(at_limit);
    REQUIRE_FALSE(reset_window);
}

TEST_CASE("HTTP endpoint defaults protect sensitive Matrix endpoints", "[http][rate-limit]")
{
    // Given
    auto constexpr post = "POST";
    auto constexpr get = "GET";
    auto constexpr put = "PUT";

    // When
    auto const login = merovingian::http::endpoint_default_rate_limit(post, "/_matrix/client/v3/login");
    auto const keys = merovingian::http::endpoint_default_rate_limit(post, "/_matrix/client/v3/keys/upload");
    auto const media = merovingian::http::endpoint_default_rate_limit(get, "/_matrix/media/v3/download/a/b");
    auto const federation = merovingian::http::endpoint_default_rate_limit(put, "/_matrix/federation/v1/send/1");
    auto const generic = merovingian::http::endpoint_default_rate_limit(get, "/_matrix/client/v3/sync");

    // Then
    REQUIRE(login.max_requests == 5U);
    REQUIRE(keys.max_requests == 30U);
    REQUIRE(media.max_requests == 20U);
    REQUIRE(federation.max_requests == 120U);
    REQUIRE(generic.max_requests == 60U);
}

TEST_CASE("HTTP rate limit summary is stable", "[http][rate-limit]")
{
    // Given
    auto const policy = merovingian::http::RateLimitPolicy{5U, 60U};

    // When
    auto const summary = merovingian::http::rate_limit_summary(policy);

    // Then
    REQUIRE(summary.find("max_requests=5") != std::string::npos);
    REQUIRE(summary.find("window_seconds=60") != std::string::npos);
}
