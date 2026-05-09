// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/http/connection_guard.hpp>

#include <catch2/catch_test_macros.hpp>

#include <string>

TEST_CASE("HTTP slowloris policy validates conservative bounds", "[http][slowloris]")
{
    auto const policy = merovingian::http::SlowlorisPolicy{};

    REQUIRE(merovingian::http::slowloris_policy_is_valid(policy));
    REQUIRE(policy.min_bytes_per_second == 64U);
    REQUIRE(policy.grace_seconds == 5U);
    REQUIRE(policy.header_deadline_seconds == 30U);
}

TEST_CASE("HTTP slowloris guard allows grace period and rejects slow progress", "[http][slowloris]")
{
    auto const policy = merovingian::http::SlowlorisPolicy{};

    REQUIRE_FALSE(merovingian::http::request_progress_is_too_slow({0U, 5U}, policy));
    REQUIRE(merovingian::http::request_progress_is_too_slow({63U, 6U}, policy));
    REQUIRE_FALSE(merovingian::http::request_progress_is_too_slow({64U, 6U}, policy));
    REQUIRE(merovingian::http::request_progress_is_too_slow({4096U, 31U}, policy));
}

TEST_CASE("HTTP slowloris policy summary is stable", "[http][slowloris]")
{
    auto const summary = merovingian::http::slowloris_policy_summary(merovingian::http::SlowlorisPolicy{});

    REQUIRE(summary.find("min_bytes_per_second=64") != std::string::npos);
    REQUIRE(summary.find("grace_seconds=5") != std::string::npos);
    REQUIRE(summary.find("header_deadline_seconds=30") != std::string::npos);
}
