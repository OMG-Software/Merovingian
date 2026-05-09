// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/http/request.hpp>

#include <catch2/catch_test_macros.hpp>

#include <string>

TEST_CASE("HTTP request head parser accepts bounded simple requests", "[http][request]")
{
    // Given
    auto constexpr input = "GET /_matrix/client/v3/login HTTP/1.1\r\nHost: example.org\r\nContent-Length: 0\r\n\r\n";

    // When
    auto const parsed = merovingian::http::parse_request_head(input);

    // Then
    REQUIRE(parsed.error == merovingian::http::RequestErrorCode::none);
    REQUIRE(parsed.request.method == "GET");
    REQUIRE(parsed.request.target == "/_matrix/client/v3/login");
    REQUIRE(parsed.request.headers.size() == 2U);
    REQUIRE(parsed.request.has_content_length);
    REQUIRE(parsed.request.content_length == 0U);
}

TEST_CASE("HTTP request head parser rejects malformed request lines", "[http][request]")
{
    // Given
    auto constexpr input = "GET / missing-version\r\n\r\n";

    // When
    auto const parsed = merovingian::http::parse_request_head(input);
    auto const status = merovingian::http::request_error_status(parsed.error);

    // Then
    REQUIRE(parsed.error == merovingian::http::RequestErrorCode::malformed_request_line);
    REQUIRE(status == 400U);
}

TEST_CASE("HTTP request head parser rejects invalid methods and targets", "[http][request]")
{
    // Given
    auto constexpr invalid_method_input = "BAD/METHOD / HTTP/1.1\r\n\r\n";
    auto constexpr invalid_target_input = "GET /bad target HTTP/1.1\r\n\r\n";

    // When
    auto const invalid_method = merovingian::http::parse_request_head(invalid_method_input);
    auto const invalid_target = merovingian::http::parse_request_head(invalid_target_input);

    // Then
    REQUIRE(invalid_method.error == merovingian::http::RequestErrorCode::invalid_method);
    REQUIRE(invalid_target.error == merovingian::http::RequestErrorCode::malformed_request_line);
}

TEST_CASE("HTTP request head parser rejects duplicate mismatched content length", "[http][request]")
{
    // Given
    auto constexpr input = "POST /upload HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n";

    // When
    auto const parsed = merovingian::http::parse_request_head(input);

    // Then
    REQUIRE(parsed.error == merovingian::http::RequestErrorCode::duplicate_content_length);
}

TEST_CASE("HTTP request head parser rejects unsupported transfer encoding", "[http][request]")
{
    // Given
    auto constexpr input = "POST /upload HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n";

    // When
    auto const parsed = merovingian::http::parse_request_head(input);
    auto const status = merovingian::http::request_error_status(parsed.error);

    // Then
    REQUIRE(parsed.error == merovingian::http::RequestErrorCode::unsupported_transfer_encoding);
    REQUIRE(status == 501U);
}

TEST_CASE("HTTP request errors have stable names", "[http][request]")
{
    // Given
    auto constexpr no_error = merovingian::http::RequestErrorCode::none;
    auto constexpr body_too_large = merovingian::http::RequestErrorCode::body_too_large;

    // When
    auto const no_error_name = std::string{merovingian::http::request_error_name(no_error)};
    auto const body_too_large_name = std::string{merovingian::http::request_error_name(body_too_large)};

    // Then
    REQUIRE(no_error_name == "none");
    REQUIRE(body_too_large_name == "body_too_large");
}
