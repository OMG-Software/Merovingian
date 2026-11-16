// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// oauth::parse_scope (spec v1.19 Client-Server API "Scope", RFC 6749 section 3.3; ADR-0769).

#include "merovingian/core/ErrorCode.hpp"
#include "merovingian/oauth/OAuthErrorCodes.hpp"
#include "merovingian/oauth/ScopeParser.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <string>
#include <string_view>
#include <variant>

namespace
{

using merovingian::oauth::GrantedScope;
using merovingian::oauth::OAuthRefusal;
using merovingian::oauth::parse_scope;

constexpr auto api = std::string_view{"urn:matrix:client:api:*"};
constexpr auto device = std::string_view{"urn:matrix:client:device:"};

[[nodiscard]] auto scope_of(std::string_view first, std::string_view second) -> std::string
{
    return std::string{first} + " " + std::string{second};
}

[[nodiscard]] auto is_invalid_scope(std::variant<GrantedScope, OAuthRefusal> const& result) -> bool
{
    auto const* refusal = std::get_if<OAuthRefusal>(&result);
    return refusal != nullptr && refusal->error_code == merovingian::oauth::error_invalid_scope;
}

} // namespace

SCENARIO("A scope with the API token and one device token is granted in canonical order", "[oauth][scope]")
{
    GIVEN("the device token first, the API token second and an unknown token between them")
    {
        auto const scope = std::string{device} + "AbCdEf0123-._~ urn:example:unknown " + std::string{api};

        WHEN("it is parsed")
        {
            auto const result = parse_scope(scope);

            THEN("the device ID is read, the unknown token is dropped and the order is canonical")
            {
                auto const* granted = std::get_if<GrantedScope>(&result);
                REQUIRE(granted != nullptr);
                REQUIRE(granted->device_id == "AbCdEf0123-._~");
                REQUIRE(granted->scope == "urn:matrix:client:api:* urn:matrix:client:device:AbCdEf0123-._~");
            }
        }
    }
}

SCENARIO("A scope with no device token, or with two, is invalid_scope", "[oauth][scope][security]")
{
    GIVEN("scopes with zero device tokens, two different ones and the same one twice")
    {
        auto const none = std::string{api};
        auto const two =
            scope_of(scope_of(api, std::string{device} + "AAAAAAAAAA"), std::string{device} + "BBBBBBBBBB");
        auto const same_twice =
            scope_of(scope_of(api, std::string{device} + "AAAAAAAAAA"), std::string{device} + "AAAAAAAAAA");

        WHEN("each is parsed")
        {
            THEN("each is refused with invalid_scope")
            {
                REQUIRE(is_invalid_scope(parse_scope(none)));
                REQUIRE(is_invalid_scope(parse_scope(two)));
                REQUIRE(is_invalid_scope(parse_scope(same_twice)));
            }
        }
    }
}

SCENARIO("A scope without the API token is invalid_scope", "[oauth][scope]")
{
    GIVEN("a device token alone, and a device token with a narrower API token")
    {
        auto const alone = std::string{device} + "AAAAAAAAAA";
        auto const narrower = scope_of("urn:matrix:client:api:read:*", alone);

        WHEN("each is parsed")
        {
            THEN("each is refused")
            {
                REQUIRE(is_invalid_scope(parse_scope(alone)));
                REQUIRE(is_invalid_scope(parse_scope(narrower)));
            }
        }
    }
}

SCENARIO("The unstable MSC2967 token forms are not known", "[oauth][scope]")
{
    GIVEN("a scope written only in the org.matrix.msc2967 forms")
    {
        auto const scope = std::string{"urn:matrix:org.matrix.msc2967.client:api:* "
                                       "urn:matrix:org.matrix.msc2967.client:device:AAAAAAAAAA"};

        WHEN("it is parsed")
        {
            auto const result = parse_scope(scope);

            THEN("both are dropped as unknown, so the scope is refused")
            {
                REQUIRE(is_invalid_scope(result));
            }
        }
    }
}

SCENARIO("Spacing must be single spaces between tokens", "[oauth][scope][boundary]")
{
    GIVEN("a valid pair of tokens")
    {
        auto const good = scope_of(api, std::string{device} + "AAAAAAAAAA");

        WHEN("it is parsed with a leading, trailing or doubled space, a tab, or empty")
        {
            THEN("each variant is refused and the plain one is granted")
            {
                REQUIRE(std::holds_alternative<GrantedScope>(parse_scope(good)));
                REQUIRE(is_invalid_scope(parse_scope(" " + good)));
                REQUIRE(is_invalid_scope(parse_scope(good + " ")));
                REQUIRE(is_invalid_scope(parse_scope(std::string{api} + "  " + std::string{device} + "AAAAAAAAAA")));
                REQUIRE(is_invalid_scope(parse_scope(std::string{api} + "\t" + std::string{device} + "AAAAAAAAAA")));
                REQUIRE(is_invalid_scope(parse_scope("")));
                REQUIRE(is_invalid_scope(parse_scope(" ")));
            }
        }
    }
}

SCENARIO("A byte outside the scope-token set refuses the whole scope", "[oauth][scope][security]")
{
    GIVEN("an unknown token carrying a quote, a backslash, a NUL, DEL or a non-ASCII byte")
    {
        auto const base = scope_of(api, std::string{device} + "AAAAAAAAAA");
        auto const bad = std::string_view{"\"\\\x7f\x80"};

        WHEN("each is added to a valid scope")
        {
            THEN("each scope is refused, not just the token dropped")
            {
                for (auto const value : bad)
                {
                    REQUIRE(is_invalid_scope(parse_scope(base + " x" + std::string(1U, value))));
                }
                auto with_nul = base + " x";
                with_nul.push_back('\0');
                REQUIRE(is_invalid_scope(parse_scope(with_nul)));
            }
        }
    }
}

SCENARIO("The device ID must be 10 or more unreserved characters", "[oauth][scope][boundary]")
{
    GIVEN("device IDs of 9 and 10 characters, and ones holding allowed scope characters outside unreserved")
    {
        auto const nine = scope_of(api, std::string{device} + "AAAAAAAAA");
        auto const ten = scope_of(api, std::string{device} + "AAAAAAAAAA");
        auto const with_colon = scope_of(api, std::string{device} + "AAAAA:AAAAA");
        auto const with_slash = scope_of(api, std::string{device} + "AAAAA/AAAAA");
        auto const with_percent = scope_of(api, std::string{device} + "AAAAA%41AAAA");
        auto const empty = scope_of(api, device);

        WHEN("each is parsed")
        {
            THEN("only the ten-character ID is granted")
            {
                REQUIRE(is_invalid_scope(parse_scope(nine)));
                REQUIRE(std::holds_alternative<GrantedScope>(parse_scope(ten)));
                REQUIRE(is_invalid_scope(parse_scope(with_colon)));
                REQUIRE(is_invalid_scope(parse_scope(with_slash)));
                REQUIRE(is_invalid_scope(parse_scope(with_percent)));
                REQUIRE(is_invalid_scope(parse_scope(empty)));
            }
        }
    }
}

SCENARIO("The device ID length is capped by auth::device_id_is_valid", "[oauth][scope][boundary]")
{
    GIVEN("device IDs of 255 and 256 characters")
    {
        auto const longest = scope_of(api, std::string{device} + std::string(255U, 'a'));
        auto const too_long = scope_of(api, std::string{device} + std::string(256U, 'a'));

        WHEN("each is parsed")
        {
            THEN("255 is granted and 256 is refused")
            {
                REQUIRE(std::holds_alternative<GrantedScope>(parse_scope(longest)));
                REQUIRE(is_invalid_scope(parse_scope(too_long)));
            }
        }
    }
}

SCENARIO("The scope byte and token caps refuse rather than truncate", "[oauth][scope][boundary]")
{
    GIVEN("a scope of more than 2048 bytes and one of 33 tokens")
    {
        auto const base = scope_of(api, std::string{device} + "AAAAAAAAAA");
        auto const long_scope = base + " " + std::string(2048U, 'x');
        auto many = base;
        for (auto index = std::size_t{0U}; index < 31U; ++index)
        {
            many.append(" t");
        }

        WHEN("each is parsed")
        {
            auto const long_result = parse_scope(long_scope);
            auto const many_result = parse_scope(many);

            THEN("each is invalid_scope with ErrorCode::invalid_argument and a message that quotes nothing")
            {
                REQUIRE(is_invalid_scope(long_result));
                REQUIRE(is_invalid_scope(many_result));
                auto const& refusal = std::get<OAuthRefusal>(many_result);
                REQUIRE(refusal.error.code() == merovingian::core::ErrorCode::invalid_argument);
                REQUIRE(refusal.error.message().find("AAAA") == std::string::npos);
                auto at_cap = base;
                for (auto index = std::size_t{0U}; index < 30U; ++index)
                {
                    at_cap.append(" t");
                }
                REQUIRE(std::holds_alternative<GrantedScope>(parse_scope(at_cap)));
            }
        }
    }
}
