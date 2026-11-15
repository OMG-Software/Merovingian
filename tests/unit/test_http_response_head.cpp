// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// http::format_response_head and http::format_response: the bytes every listener writes for a handler's
// LocalHttpResponse (ADR-0767). A handler's headers are matched case-insensitively, and a header that could split the
// response or contradict the transport's framing refuses the response instead of being dropped.

#include "merovingian/core/ErrorCode.hpp"
#include "merovingian/http/ConnectionPreference.hpp"
#include "merovingian/http/ResponseHead.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace
{

using Headers = std::vector<std::pair<std::string, std::string>>;
using merovingian::http::ConnectionPreference;

[[nodiscard]] auto text_of(std::variant<std::string, merovingian::core::Error> const& formatted) -> std::string
{
    auto const* text = std::get_if<std::string>(&formatted);
    return text == nullptr ? std::string{} : *text;
}

[[nodiscard]] auto is_refused(std::variant<std::string, merovingian::core::Error> const& formatted) -> bool
{
    auto const* error = std::get_if<merovingian::core::Error>(&formatted);
    return error != nullptr && error->code() == merovingian::core::ErrorCode::invalid_argument;
}

[[nodiscard]] auto occurrences(std::string_view text, std::string_view needle) -> std::size_t
{
    auto count = std::size_t{0U};
    for (auto at = text.find(needle); at != std::string_view::npos; at = text.find(needle, at + 1U))
    {
        ++count;
    }
    return count;
}

} // namespace

SCENARIO("An HTML page with its security headers reaches the wire as the handler built it",
         "[http][response-head][oauth]")
{
    GIVEN("a 200 HTML response with a policy, a cookie and the type spelled in lower case")
    {
        auto const body = std::string_view{"<!DOCTYPE html><title>Sign in</title>"};
        auto const headers = Headers{
            {"content-type",            "text/html; charset=utf-8"                                             },
            {"Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'"                           },
            {"Set-Cookie",              "__Host-oauth=abc; Max-Age=600; Path=/; Secure; HttpOnly; SameSite=Lax"},
            {"Set-Cookie",              "__Host-old=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax"       },
        };

        WHEN("it is formatted for a kept-alive connection")
        {
            auto const formatted =
                merovingian::http::format_response(200U, body, headers, ConnectionPreference::keep_alive, 30U);

            THEN("the bytes are exact: one Content-Type, the handler's, and both cookies")
            {
                REQUIRE(text_of(formatted) ==
                        "HTTP/1.1 200 OK\r\n"
                        "Content-Security-Policy: default-src 'none'; frame-ancestors 'none'\r\n"
                        "Set-Cookie: __Host-oauth=abc; Max-Age=600; Path=/; Secure; HttpOnly; SameSite=Lax\r\n"
                        "Set-Cookie: __Host-old=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax\r\n"
                        "X-Content-Type-Options: nosniff\r\n"
                        "Content-Length: 37\r\n"
                        "Content-Type: text/html; charset=utf-8\r\n"
                        "Connection: keep-alive\r\n"
                        "Keep-Alive: timeout=30\r\n"
                        "\r\n"
                        "<!DOCTYPE html><title>Sign in</title>");
            }
        }
    }

    GIVEN("a 302 and a 303 redirect with a Location and an HTML body")
    {
        auto const headers = Headers{
            {"Location",     "https://client.example/cb?code=c&state=s"},
            {"CONTENT-TYPE", "text/html; charset=utf-8"                },
        };

        WHEN("each is formatted")
        {
            auto const found = merovingian::http::format_response(302U, "", headers, ConnectionPreference::close, 0U);
            auto const see_other =
                merovingian::http::format_response(303U, "<p>go</p>", headers, ConnectionPreference::close, 0U);

            THEN("the status lines carry the right phrases and the Location is written once")
            {
                REQUIRE(text_of(found) == "HTTP/1.1 302 Found\r\n"
                                          "Location: https://client.example/cb?code=c&state=s\r\n"
                                          "X-Content-Type-Options: nosniff\r\n"
                                          "Content-Length: 0\r\n"
                                          "Content-Type: text/html; charset=utf-8\r\n"
                                          "Connection: close\r\n"
                                          "\r\n");
                REQUIRE(text_of(see_other).starts_with("HTTP/1.1 303 See Other\r\n"));
                REQUIRE(text_of(see_other).ends_with("\r\n\r\n<p>go</p>"));
                REQUIRE(occurrences(text_of(see_other), "Content-Type:") == 1U);
            }
        }
    }

    GIVEN("a response with no Content-Type and a handler's own nosniff in another case")
    {
        auto const headers = Headers{
            {"x-content-type-options", "NoSniff"},
        };

        WHEN("it is formatted")
        {
            auto const formatted =
                merovingian::http::format_response_head(200U, 2U, headers, ConnectionPreference::close, 0U);

            THEN("the type is JSON and nosniff is written once")
            {
                auto const text = text_of(formatted);
                REQUIRE(text.find("\r\nContent-Type: application/json\r\n") != std::string::npos);
                REQUIRE(occurrences(text, "nosniff") + occurrences(text, "NoSniff") == 1U);
            }
        }
    }
}

SCENARIO("Statuses the server answers with carry their reason phrase", "[http][response-head]")
{
    GIVEN("every status the code base returns")
    {
        WHEN("each phrase is asked for")
        {
            THEN("each has its RFC 9110 phrase, and an unlisted status has none")
            {
                REQUIRE(merovingian::http::reason_phrase(200U) == "OK");
                REQUIRE(merovingian::http::reason_phrase(202U) == "Accepted");
                REQUIRE(merovingian::http::reason_phrase(302U) == "Found");
                REQUIRE(merovingian::http::reason_phrase(303U) == "See Other");
                REQUIRE(merovingian::http::reason_phrase(409U) == "Conflict");
                REQUIRE(merovingian::http::reason_phrase(415U) == "Unsupported Media Type");
                REQUIRE(merovingian::http::reason_phrase(451U) == "Unavailable For Legal Reasons");
                REQUIRE(merovingian::http::reason_phrase(504U) == "Gateway Timeout");
                REQUIRE(merovingian::http::reason_phrase(507U) == "Insufficient Storage");
                REQUIRE(merovingian::http::reason_phrase(418U).empty());
                auto const head =
                    merovingian::http::format_response_head(418U, 0U, {}, ConnectionPreference::close, 0U);
                REQUIRE(text_of(head).starts_with("HTTP/1.1 418 \r\n"));
            }
        }
    }
}

SCENARIO("A response whose headers could split it or contradict its framing is refused",
         "[http][response-head][security]")
{
    GIVEN("headers carrying CR or LF, or a name that is not a token")
    {
        auto const hostile = std::vector<Headers>{
            {{"Location", "https://a.example/\r\nSet-Cookie: x=y"}},
            {{"Location", "https://a.example/\nX: y"}},
            {{"Location", "https://a.example/\r"}},
            {{"Set-Cookie", std::string{"a=b\0c", 5U}}},
            {{"Bad Name", "v"}},
            {{"Bad:Name", "v"}},
            {{"", "v"}},
        };

        WHEN("each is formatted")
        {
            THEN("each is refused, never written with the bad header dropped")
            {
                for (auto const& headers : hostile)
                {
                    REQUIRE(is_refused(
                        merovingian::http::format_response(302U, "", headers, ConnectionPreference::close, 0U)));
                }
            }
        }
    }

    GIVEN("a handler that sets a framing header in any case")
    {
        auto const hostile = std::vector<Headers>{
            {{"Content-Length", "0"}},      {{"content-length", "0"}},     {{"Transfer-Encoding", "chunked"}},
            {{"connection", "keep-alive"}}, {{"Keep-Alive", "timeout=5"}},
        };

        WHEN("each is formatted")
        {
            THEN("each is refused")
            {
                for (auto const& headers : hostile)
                {
                    REQUIRE(is_refused(
                        merovingian::http::format_response(200U, "{}", headers, ConnectionPreference::close, 0U)));
                }
            }
        }
    }

    GIVEN("two Content-Type headers spelled differently, or a weakened nosniff")
    {
        auto const two_types = Headers{
            {"Content-Type", "text/html; charset=utf-8"},
            {"content-type", "application/json"        },
        };
        auto const two_nosniff = Headers{
            {"X-Content-Type-Options", "nosniff"},
            {"x-content-type-options", "nosniff"},
        };
        auto const weak_nosniff = Headers{
            {"X-Content-Type-Options", "sniff"},
        };

        WHEN("each is formatted")
        {
            auto const types = merovingian::http::format_response(200U, "", two_types, ConnectionPreference::close, 0U);
            auto const repeated =
                merovingian::http::format_response(200U, "", two_nosniff, ConnectionPreference::close, 0U);
            auto const weakened =
                merovingian::http::format_response(200U, "", weak_nosniff, ConnectionPreference::close, 0U);

            THEN("each is refused, so a response can never carry two types")
            {
                REQUIRE(is_refused(types));
                REQUIRE(is_refused(repeated));
                REQUIRE(is_refused(weakened));
            }
        }
    }

    GIVEN("statuses outside 200-599")
    {
        WHEN("each is formatted")
        {
            THEN("each is refused")
            {
                for (auto const status : {std::uint16_t{0U}, std::uint16_t{101U}, std::uint16_t{199U},
                                          std::uint16_t{600U}, std::uint16_t{999U}})
                {
                    REQUIRE(is_refused(
                        merovingian::http::format_response(status, "", {}, ConnectionPreference::close, 0U)));
                }
            }
        }
    }
}
