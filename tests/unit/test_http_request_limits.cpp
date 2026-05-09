// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/http/request_limits.hpp>

#include <catch2/catch_test_macros.hpp>

#include <string>

TEST_CASE("HTTP request limits have conservative defaults", "[http][limits]")
{
    // Given
    auto const limits = merovingian::http::RequestLimits{};

    // When
    auto const valid = merovingian::http::request_limits_are_valid(limits);

    // Then
    REQUIRE(valid);
    REQUIRE(limits.max_start_line_bytes == 8192U);
    REQUIRE(limits.max_header_bytes == 32768U);
    REQUIRE(limits.max_header_count == 100U);
    REQUIRE(limits.max_body_bytes == 1048576U);
}

TEST_CASE("HTTP request limits reject unsafe bounds", "[http][limits]")
{
    // Given
    auto limits = merovingian::http::RequestLimits{};
    limits.max_start_line_bytes = 0U;
    limits.max_header_bytes = 70000U;
    limits.max_header_count = 0U;
    limits.max_body_bytes = 67108865U;

    // When
    auto const findings = merovingian::http::validate_request_limits(limits);
    auto const valid = merovingian::http::request_limits_are_valid(limits);

    // Then
    REQUIRE(findings.size() == 4U);
    REQUIRE_FALSE(valid);
}

TEST_CASE("HTTP method token validation follows strict token characters", "[http][limits]")
{
    // Given
    auto constexpr get = "GET";
    auto constexpr m_search = "M-SEARCH";
    auto constexpr empty = "";
    auto constexpr bad_space = "BAD METHOD";
    auto constexpr bad_slash = "bad/method";

    // When
    auto const get_valid = merovingian::http::method_token_is_valid(get);
    auto const m_search_valid = merovingian::http::method_token_is_valid(m_search);
    auto const empty_valid = merovingian::http::method_token_is_valid(empty);
    auto const bad_space_valid = merovingian::http::method_token_is_valid(bad_space);
    auto const bad_slash_valid = merovingian::http::method_token_is_valid(bad_slash);

    // Then
    REQUIRE(get_valid);
    REQUIRE(m_search_valid);
    REQUIRE_FALSE(empty_valid);
    REQUIRE_FALSE(bad_space_valid);
    REQUIRE_FALSE(bad_slash_valid);
}

TEST_CASE("HTTP request target validation rejects empty and control-space targets", "[http][limits]")
{
    // Given
    auto constexpr client_path = "/_matrix/client/v3/login";
    auto constexpr query_path = "/path?query=value";
    auto constexpr empty = "";
    auto constexpr space_path = "/bad path";
    auto constexpr newline_path = "/bad\npath";

    // When
    auto const client_path_valid = merovingian::http::request_target_is_valid(client_path);
    auto const query_path_valid = merovingian::http::request_target_is_valid(query_path);
    auto const empty_valid = merovingian::http::request_target_is_valid(empty);
    auto const space_path_valid = merovingian::http::request_target_is_valid(space_path);
    auto const newline_path_valid = merovingian::http::request_target_is_valid(newline_path);

    // Then
    REQUIRE(client_path_valid);
    REQUIRE(query_path_valid);
    REQUIRE_FALSE(empty_valid);
    REQUIRE_FALSE(space_path_valid);
    REQUIRE_FALSE(newline_path_valid);
}

TEST_CASE("HTTP request line limit includes method target and version", "[http][limits]")
{
    // Given
    auto limits = merovingian::http::RequestLimits{};
    limits.max_start_line_bytes = 19U;

    // When
    auto const within_limit = merovingian::http::request_line_is_within_limit("GET", "/login", limits);
    auto const over_limit = merovingian::http::request_line_is_within_limit("GET", "/too-long", limits);

    // Then
    REQUIRE(within_limit);
    REQUIRE_FALSE(over_limit);
}

TEST_CASE("HTTP request limits summary is stable for startup diagnostics", "[http][limits]")
{
    // Given
    auto const limits = merovingian::http::RequestLimits{};

    // When
    auto const summary = merovingian::http::request_limits_summary(limits);

    // Then
    REQUIRE(summary.find("max_start_line_bytes=8192") != std::string::npos);
    REQUIRE(summary.find("max_header_bytes=32768") != std::string::npos);
    REQUIRE(summary.find("max_header_count=100") != std::string::npos);
    REQUIRE(summary.find("max_body_bytes=1048576") != std::string::npos);
}
