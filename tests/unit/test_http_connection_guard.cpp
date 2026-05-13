// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/http/connection_guard.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

SCENARIO("HTTP slowloris policy validates conservative bounds", "[http][slowloris]")
{
    GIVEN("the default slowloris policy")
    {
        auto const policy = merovingian::http::SlowlorisPolicy{};

        WHEN("the policy is validated")
        {
            auto const valid = merovingian::http::slowloris_policy_is_valid(policy);

            THEN("the conservative bounds are accepted")
            {
                REQUIRE(valid);
                REQUIRE(policy.min_bytes_per_second == 64U);
                REQUIRE(policy.grace_seconds == 5U);
                REQUIRE(policy.header_deadline_seconds == 30U);
            }
        }
    }
}

SCENARIO("HTTP slowloris guard allows grace period and rejects slow progress", "[http][slowloris]")
{
    GIVEN("the default slowloris policy")
    {
        auto const policy = merovingian::http::SlowlorisPolicy{};

        WHEN("request progress samples are evaluated")
        {
            auto const grace_period_too_slow = merovingian::http::request_progress_is_too_slow({0U, 5U}, policy);
            auto const under_rate_too_slow = merovingian::http::request_progress_is_too_slow({63U, 6U}, policy);
            auto const at_rate_too_slow = merovingian::http::request_progress_is_too_slow({64U, 6U}, policy);
            auto const deadline_exceeded_too_slow = merovingian::http::request_progress_is_too_slow({4096U, 31U}, policy);

            THEN("only slow or deadline-exceeded progress is rejected")
            {
                REQUIRE_FALSE(grace_period_too_slow);
                REQUIRE(under_rate_too_slow);
                REQUIRE_FALSE(at_rate_too_slow);
                REQUIRE(deadline_exceeded_too_slow);
            }
        }
    }
}

SCENARIO("HTTP slowloris policy summary is stable", "[http][slowloris]")
{
    GIVEN("the default slowloris policy")
    {
        auto const policy = merovingian::http::SlowlorisPolicy{};

        WHEN("the policy summary is generated")
        {
            auto const summary = merovingian::http::slowloris_policy_summary(policy);

            THEN("the expected fields are present")
            {
                REQUIRE(summary.find("min_bytes_per_second=64") != std::string::npos);
                REQUIRE(summary.find("grace_seconds=5") != std::string::npos);
                REQUIRE(summary.find("header_deadline_seconds=30") != std::string::npos);
            }
        }
    }
}
