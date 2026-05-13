// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/http/request_limits.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

SCENARIO("HTTP request limits have conservative defaults", "[http][limits]")
{
    GIVEN("the default HTTP request limits")
    {
        auto const limits = merovingian::http::RequestLimits{};

        WHEN("the limits are validated")
        {
            auto const valid = merovingian::http::request_limits_are_valid(limits);

            THEN("the conservative defaults are accepted")
            {
                REQUIRE(valid);
                REQUIRE(limits.max_start_line_bytes == 8192U);
                REQUIRE(limits.max_header_bytes == 32768U);
                REQUIRE(limits.max_header_count == 100U);
                REQUIRE(limits.max_body_bytes == 1048576U);
            }
        }
    }
}

SCENARIO("HTTP request limits reject unsafe bounds", "[http][limits]")
{
    GIVEN("request limits with unsafe bounds")
    {
        auto limits = merovingian::http::RequestLimits{};
        limits.max_start_line_bytes = 0U;
        limits.max_header_bytes = 70000U;
        limits.max_header_count = 0U;
        limits.max_body_bytes = 67108865U;

        WHEN("the limits are validated")
        {
            auto const findings = merovingian::http::validate_request_limits(limits);
            auto const valid = merovingian::http::request_limits_are_valid(limits);

            THEN("all unsafe bounds are reported")
            {
                REQUIRE(findings.size() == 4U);
                REQUIRE_FALSE(valid);
            }
        }
    }
}

SCENARIO("HTTP method token validation follows strict token characters", "[http][limits]")
{
    GIVEN("valid and invalid method tokens")
    {
        auto constexpr get = "GET";
        auto constexpr m_search = "M-SEARCH";
        auto constexpr empty = "";
        auto constexpr bad_space = "BAD METHOD";
        auto constexpr bad_slash = "bad/method";

        WHEN("method tokens are validated")
        {
            auto const get_valid = merovingian::http::method_token_is_valid(get);
            auto const m_search_valid = merovingian::http::method_token_is_valid(m_search);
            auto const empty_valid = merovingian::http::method_token_is_valid(empty);
            auto const bad_space_valid = merovingian::http::method_token_is_valid(bad_space);
            auto const bad_slash_valid = merovingian::http::method_token_is_valid(bad_slash);

            THEN("only strict token syntax is accepted")
            {
                REQUIRE(get_valid);
                REQUIRE(m_search_valid);
                REQUIRE_FALSE(empty_valid);
                REQUIRE_FALSE(bad_space_valid);
                REQUIRE_FALSE(bad_slash_valid);
            }
        }
    }
}

SCENARIO("HTTP request target validation rejects empty and control-space targets", "[http][limits]")
{
    GIVEN("valid and invalid request targets")
    {
        auto constexpr client_path = "/_matrix/client/v3/login";
        auto constexpr query_path = "/path?query=value";
        auto constexpr empty = "";
        auto constexpr space_path = "/bad path";
        auto constexpr newline_path = "/bad\npath";

        WHEN("request targets are validated")
        {
            auto const client_path_valid = merovingian::http::request_target_is_valid(client_path);
            auto const query_path_valid = merovingian::http::request_target_is_valid(query_path);
            auto const empty_valid = merovingian::http::request_target_is_valid(empty);
            auto const space_path_valid = merovingian::http::request_target_is_valid(space_path);
            auto const newline_path_valid = merovingian::http::request_target_is_valid(newline_path);

            THEN("only non-empty targets without control or space characters are accepted")
            {
                REQUIRE(client_path_valid);
                REQUIRE(query_path_valid);
                REQUIRE_FALSE(empty_valid);
                REQUIRE_FALSE(space_path_valid);
                REQUIRE_FALSE(newline_path_valid);
            }
        }
    }
}

SCENARIO("HTTP request line limit includes method target and version", "[http][limits]")
{
    GIVEN("a request line byte limit")
    {
        auto limits = merovingian::http::RequestLimits{};
        limits.max_start_line_bytes = 19U;

        WHEN("request lines are checked against the limit")
        {
            auto const within_limit = merovingian::http::request_line_is_within_limit("GET", "/login", limits);
            auto const over_limit = merovingian::http::request_line_is_within_limit("GET", "/too-long", limits);

            THEN("only request lines within the full start-line size are accepted")
            {
                REQUIRE(within_limit);
                REQUIRE_FALSE(over_limit);
            }
        }
    }
}

SCENARIO("HTTP request limits summary is stable for startup diagnostics", "[http][limits]")
{
    GIVEN("the default request limits")
    {
        auto const limits = merovingian::http::RequestLimits{};

        WHEN("the request limits summary is generated")
        {
            auto const summary = merovingian::http::request_limits_summary(limits);

            THEN("the expected fields are present")
            {
                REQUIRE(summary.find("max_start_line_bytes=8192") != std::string::npos);
                REQUIRE(summary.find("max_header_bytes=32768") != std::string::npos);
                REQUIRE(summary.find("max_header_count=100") != std::string::npos);
                REQUIRE(summary.find("max_body_bytes=1048576") != std::string::npos);
            }
        }
    }
}
