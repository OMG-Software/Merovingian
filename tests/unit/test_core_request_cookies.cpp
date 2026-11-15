// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// core::RequestCookies: the Cookie request-header reader (RFC 6265 section 4.2.1, ADR-0766). A malformed or repeated
// cookie makes its own name unusable; only what no browser sends refuses the header.

#include "merovingian/core/ErrorCode.hpp"
#include "merovingian/core/RequestCookies.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <variant>

namespace
{

using merovingian::core::ErrorCode;
using merovingian::core::RequestCookies;

[[nodiscard]] auto refusal_code(std::variant<RequestCookies, merovingian::core::Error> const& parsed) -> ErrorCode
{
    auto const* error = std::get_if<merovingian::core::Error>(&parsed);
    return error == nullptr ? ErrorCode::none : error->code();
}

} // namespace

SCENARIO("A Cookie header is read into name and value pairs", "[core][cookie]")
{
    GIVEN("a header as a browser writes it")
    {
        auto const header = std::string_view{"__Host-oauth=AbC123_-.~; theme=dark; empty="};

        WHEN("it is parsed")
        {
            auto const parsed = RequestCookies::parse(header);

            THEN("each cookie is found by its exact name, with no decoding")
            {
                auto const* cookies = std::get_if<RequestCookies>(&parsed);
                REQUIRE(cookies != nullptr);
                REQUIRE(cookies->size() == 3U);
                REQUIRE(cookies->find("__Host-oauth") == std::optional<std::string_view>{"AbC123_-.~"});
                REQUIRE(cookies->find("theme") == std::optional<std::string_view>{"dark"});
                REQUIRE(cookies->find("empty") == std::optional<std::string_view>{""});
                REQUIRE_FALSE(cookies->find("Theme").has_value());
                REQUIRE_FALSE(cookies->find("absent").has_value());
                REQUIRE_FALSE(cookies->find("").has_value());
            }
        }

        WHEN("a value holds a percent escape")
        {
            auto const parsed = RequestCookies::parse("a=%41");

            THEN("it is returned as sent")
            {
                auto const* cookies = std::get_if<RequestCookies>(&parsed);
                REQUIRE(cookies != nullptr);
                REQUIRE(cookies->find("a") == std::optional<std::string_view>{"%41"});
            }
        }
    }

    GIVEN("an empty header and one with spaces around and between the pairs")
    {
        WHEN("both are parsed")
        {
            auto const empty = RequestCookies::parse("");
            auto const spaced = RequestCookies::parse("  a=1 ;\tb=2  ");

            THEN("the empty one has no cookies and the spaces are trimmed")
            {
                auto const* none = std::get_if<RequestCookies>(&empty);
                REQUIRE(none != nullptr);
                REQUIRE(none->size() == 0U);
                auto const* cookies = std::get_if<RequestCookies>(&spaced);
                REQUIRE(cookies != nullptr);
                REQUIRE(cookies->find("a") == std::optional<std::string_view>{"1"});
                REQUIRE(cookies->find("b") == std::optional<std::string_view>{"2"});
            }
        }
    }
}

SCENARIO("A repeated or malformed cookie makes its own name unusable", "[core][cookie][security]")
{
    GIVEN("a header that sends one name twice")
    {
        WHEN("it is parsed")
        {
            auto const parsed = RequestCookies::parse("__Host-s=first; other=1; __Host-s=second");

            THEN("neither copy is returned, and the other cookie still is")
            {
                auto const* cookies = std::get_if<RequestCookies>(&parsed);
                REQUIRE(cookies != nullptr);
                REQUIRE_FALSE(cookies->find("__Host-s").has_value());
                REQUIRE(cookies->find("other") == std::optional<std::string_view>{"1"});
            }
        }
    }

    GIVEN("a header with a well-formed copy of a name and a malformed one")
    {
        WHEN("it is parsed")
        {
            auto const parsed = RequestCookies::parse("s=good; s=\"quoted\"");

            THEN("the name answers nothing")
            {
                auto const* cookies = std::get_if<RequestCookies>(&parsed);
                REQUIRE(cookies != nullptr);
                REQUIRE_FALSE(cookies->find("s").has_value());
            }
        }
    }

    GIVEN("pairs that break the cookie grammar beside a good one")
    {
        WHEN("each is parsed")
        {
            auto const no_equals = RequestCookies::parse("flag; good=1");
            auto const quoted = RequestCookies::parse("q=\"abc\"; good=1");
            auto const with_space = RequestCookies::parse("v=a b; good=1");
            auto const with_comma = RequestCookies::parse("v=a,b; good=1");
            auto const with_backslash = RequestCookies::parse("v=a\\b; good=1");
            auto const non_ascii = RequestCookies::parse("v=caf\xC3\xA9; good=1");
            auto const bad_name = RequestCookies::parse("na(me=1; good=1");
            auto const empty_name = RequestCookies::parse("=1; good=1");
            auto const doubled = RequestCookies::parse("good=1;; x=2;");

            THEN("the malformed name answers nothing and the good cookie is still read")
            {
                for (auto const* parsed : {&no_equals, &quoted, &with_space, &with_comma, &with_backslash, &non_ascii,
                                           &bad_name, &empty_name, &doubled})
                {
                    auto const* cookies = std::get_if<RequestCookies>(parsed);
                    REQUIRE(cookies != nullptr);
                    REQUIRE(cookies->find("good") == std::optional<std::string_view>{"1"});
                }
                REQUIRE_FALSE(std::get<RequestCookies>(no_equals).find("flag").has_value());
                REQUIRE_FALSE(std::get<RequestCookies>(quoted).find("q").has_value());
                REQUIRE_FALSE(std::get<RequestCookies>(with_space).find("v").has_value());
                REQUIRE_FALSE(std::get<RequestCookies>(with_comma).find("v").has_value());
                REQUIRE_FALSE(std::get<RequestCookies>(with_backslash).find("v").has_value());
                REQUIRE_FALSE(std::get<RequestCookies>(non_ascii).find("v").has_value());
                REQUIRE_FALSE(std::get<RequestCookies>(bad_name).find("na(me").has_value());
                REQUIRE(std::get<RequestCookies>(doubled).find("x") == std::optional<std::string_view>{"2"});
            }
        }
    }
}

SCENARIO("A Cookie header no browser sends is refused whole", "[core][cookie][security][boundary]")
{
    GIVEN("headers with control characters")
    {
        WHEN("each is parsed")
        {
            auto const with_nul = RequestCookies::parse(std::string_view{"a=1\0b", 5U});
            auto const with_cr = RequestCookies::parse("a=1\r\nSet-Cookie: b=2");
            auto const with_del = RequestCookies::parse("a=\x7F");

            THEN("each is refused as malformed")
            {
                REQUIRE(refusal_code(with_nul) == ErrorCode::parse_failure);
                REQUIRE(refusal_code(with_cr) == ErrorCode::parse_failure);
                REQUIRE(refusal_code(with_del) == ErrorCode::parse_failure);
            }
        }
    }

    GIVEN("headers at and one past the length and cookie-count caps")
    {
        auto const long_ok = "a=" + std::string(RequestCookies::max_header_bytes - 2U, 'x');
        auto const long_over = long_ok + "x";
        auto many_ok = std::string{"c0=1"};
        for (auto index = std::size_t{1U}; index < RequestCookies::max_cookies; ++index)
        {
            many_ok += "; c" + std::to_string(index) + "=1";
        }
        auto const many_over = many_ok + "; extra=1";

        WHEN("each is parsed")
        {
            auto const at_length = RequestCookies::parse(long_ok);
            auto const past_length = RequestCookies::parse(long_over);
            auto const at_count = RequestCookies::parse(many_ok);
            auto const past_count = RequestCookies::parse(many_over);

            THEN("the caps are inclusive and one more byte or cookie is refused")
            {
                REQUIRE(refusal_code(at_length) == ErrorCode::none);
                REQUIRE(refusal_code(past_length) == ErrorCode::invalid_argument);
                REQUIRE(refusal_code(at_count) == ErrorCode::none);
                REQUIRE(std::get<RequestCookies>(at_count).size() == RequestCookies::max_cookies);
                REQUIRE(refusal_code(past_count) == ErrorCode::invalid_argument);
            }
        }
    }

    GIVEN("a refused header whose value is a session secret")
    {
        WHEN("it is parsed")
        {
            auto const parsed = RequestCookies::parse("__Host-s=session-secret-value\x01");

            THEN("the error message does not repeat the input")
            {
                auto const* error = std::get_if<merovingian::core::Error>(&parsed);
                REQUIRE(error != nullptr);
                REQUIRE(error->message().find("session-secret-value") == std::string::npos);
            }
        }
    }
}
