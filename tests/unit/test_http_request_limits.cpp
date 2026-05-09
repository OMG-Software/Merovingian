// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/http/request_limits.hpp>

#include <catch2/catch_test_macros.hpp>

#include <string>

TEST_CASE("HTTP request limits have conservative defaults", "[http][limits]")
{
    auto const limits = merovingian::http::RequestLimits{};

    REQUIRE(merovingian::http::request_limits_are_valid(limits));
    REQUIRE(limits.max_start_line_bytes == 8192U);
    REQUIRE(limits.max_header_bytes == 32768U);
    REQUIRE(limits.max_header_count == 100U);
    REQUIRE(limits.max_body_bytes == 1048576U);
}

TEST_CASE("HTTP request limits reject unsafe bounds", "[http][limits]")
{
    auto limits = merovingian::http::RequestLimits{};
    limits.max_start_line_bytes = 0U;
    limits.max_header_bytes = 70000U;
    limits.max_header_count = 0U;
    limits.max_body_bytes = 67108865U;

    auto const findings = merovingian::http::validate_request_limits(limits);

    REQUIRE(findings.size() == 4U);
    REQUIRE_FALSE(merovingian::http::request_limits_are_valid(limits));
}

TEST_CASE("HTTP method token validation follows strict token characters", "[http][limits]")
{
    REQUIRE(merovingian::http::method_token_is_valid("GET"));
    REQUIRE(merovingian::http::method_token_is_valid("M-SEARCH"));
    REQUIRE_FALSE(merovingian::http::method_token_is_valid(""));
    REQUIRE_FALSE(merovingian::http::method_token_is_valid("BAD METHOD"));
    REQUIRE_FALSE(merovingian::http::method_token_is_valid("bad/method"));
}

TEST_CASE("HTTP request target validation rejects empty and control-space targets", "[http][limits]")
{
    REQUIRE(merovingian::http::request_target_is_valid("/_matrix/client/v3/login"));
    REQUIRE(merovingian::http::request_target_is_valid("/path?query=value"));
    REQUIRE_FALSE(merovingian::http::request_target_is_valid(""));
    REQUIRE_FALSE(merovingian::http::request_target_is_valid("/bad path"));
    REQUIRE_FALSE(merovingian::http::request_target_is_valid("/bad\npath"));
}

TEST_CASE("HTTP request line limit includes method target and version", "[http][limits]")
{
    auto limits = merovingian::http::RequestLimits{};
    limits.max_start_line_bytes = 19U;

    REQUIRE(merovingian::http::request_line_is_within_limit("GET", "/login", limits));
    REQUIRE_FALSE(merovingian::http::request_line_is_within_limit("GET", "/too-long", limits));
}

TEST_CASE("HTTP request limits summary is stable for startup diagnostics", "[http][limits]")
{
    auto const summary = merovingian::http::request_limits_summary(merovingian::http::RequestLimits{});

    REQUIRE(summary.find("max_start_line_bytes=8192") != std::string::npos);
    REQUIRE(summary.find("max_header_bytes=32768") != std::string::npos);
    REQUIRE(summary.find("max_header_count=100") != std::string::npos);
    REQUIRE(summary.find("max_body_bytes=1048576") != std::string::npos);
}
