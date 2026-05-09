// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/http/request.hpp>

#include <catch2/catch_test_macros.hpp>

#include <string>

TEST_CASE("HTTP request head parser accepts bounded simple requests", "[http][request]")
{
    auto const parsed = merovingian::http::parse_request_head(
        "GET /_matrix/client/v3/login HTTP/1.1\r\nHost: example.org\r\nContent-Length: 0\r\n\r\n"
    );

    REQUIRE(parsed.error == merovingian::http::RequestErrorCode::none);
    REQUIRE(parsed.request.method == "GET");
    REQUIRE(parsed.request.target == "/_matrix/client/v3/login");
    REQUIRE(parsed.request.headers.size() == 2U);
    REQUIRE(parsed.request.has_content_length);
    REQUIRE(parsed.request.content_length == 0U);
}

TEST_CASE("HTTP request head parser rejects malformed request lines", "[http][request]")
{
    auto const parsed = merovingian::http::parse_request_head("GET / missing-version\r\n\r\n");

    REQUIRE(parsed.error == merovingian::http::RequestErrorCode::malformed_request_line);
    REQUIRE(merovingian::http::request_error_status(parsed.error) == 400U);
}

TEST_CASE("HTTP request head parser rejects invalid methods and targets", "[http][request]")
{
    auto const invalid_method = merovingian::http::parse_request_head("BAD/METHOD / HTTP/1.1\r\n\r\n");
    auto const invalid_target = merovingian::http::parse_request_head("GET /bad target HTTP/1.1\r\n\r\n");

    REQUIRE(invalid_method.error == merovingian::http::RequestErrorCode::invalid_method);
    REQUIRE(invalid_target.error == merovingian::http::RequestErrorCode::malformed_request_line);
}

TEST_CASE("HTTP request head parser rejects duplicate mismatched content length", "[http][request]")
{
    auto const parsed = merovingian::http::parse_request_head(
        "POST /upload HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n"
    );

    REQUIRE(parsed.error == merovingian::http::RequestErrorCode::duplicate_content_length);
}

TEST_CASE("HTTP request head parser rejects unsupported transfer encoding", "[http][request]")
{
    auto const parsed = merovingian::http::parse_request_head(
        "POST /upload HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"
    );

    REQUIRE(parsed.error == merovingian::http::RequestErrorCode::unsupported_transfer_encoding);
    REQUIRE(merovingian::http::request_error_status(parsed.error) == 501U);
}

TEST_CASE("HTTP request errors have stable names", "[http][request]")
{
    REQUIRE(std::string{merovingian::http::request_error_name(merovingian::http::RequestErrorCode::none)} == "none");
    REQUIRE(
        std::string{merovingian::http::request_error_name(merovingian::http::RequestErrorCode::body_too_large)}
        == "body_too_large"
    );
}
