// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// core::host_cookie and core::host_cookie_deletion: the only Set-Cookie values this server writes. Each is a
// `__Host-` cookie with Secure, HttpOnly, Path=/, a SameSite of Lax or Strict, and a Max-Age.

#include "merovingian/core/CookieSameSite.hpp"
#include "merovingian/core/ErrorCode.hpp"
#include "merovingian/core/HostCookie.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <variant>

namespace
{

using merovingian::core::CookieSameSite;

[[nodiscard]] auto text_of(std::variant<std::string, merovingian::core::Error> const& built) -> std::string
{
    auto const* text = std::get_if<std::string>(&built);
    return text == nullptr ? std::string{} : *text;
}

[[nodiscard]] auto is_refused(std::variant<std::string, merovingian::core::Error> const& built) -> bool
{
    auto const* error = std::get_if<merovingian::core::Error>(&built);
    return error != nullptr && error->code() == merovingian::core::ErrorCode::invalid_argument;
}

} // namespace

SCENARIO("A host cookie carries every attribute that keeps it to this host", "[core][cookie]")
{
    GIVEN("a name with the __Host- prefix and a token value")
    {
        WHEN("it is built with SameSite Lax and with Strict")
        {
            auto const lax = merovingian::core::host_cookie("__Host-oauth", "AbC_123", CookieSameSite::lax, 600U);
            auto const strict = merovingian::core::host_cookie("__Host-account", "x.y-z", CookieSameSite::strict, 900U);

            THEN("each is the exact Set-Cookie value")
            {
                REQUIRE(text_of(lax) == "__Host-oauth=AbC_123; Max-Age=600; Path=/; Secure; HttpOnly; SameSite=Lax");
                REQUIRE(text_of(strict) ==
                        "__Host-account=x.y-z; Max-Age=900; Path=/; Secure; HttpOnly; SameSite=Strict");
            }
        }

        WHEN("its deleting form is built")
        {
            auto const deletion = merovingian::core::host_cookie_deletion("__Host-oauth", CookieSameSite::lax);

            THEN("it is empty with Max-Age=0 and the same attributes")
            {
                REQUIRE(text_of(deletion) == "__Host-oauth=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax");
            }
        }
    }
}

SCENARIO("A host cookie refuses anything outside the cookie grammar", "[core][cookie][security]")
{
    GIVEN("names without the prefix or outside the token set")
    {
        auto const names = std::array<std::string_view, 7U>{
            "session", "__host-session", "__Host-", "__Host-a b", "__Host-a;b", "__Host-a=b", "__Host-a\r\nX: y",
        };

        WHEN("each is used to build a cookie and a deletion")
        {
            THEN("each is refused")
            {
                for (auto const name : names)
                {
                    INFO("name bytes: " << name.size());
                    REQUIRE(is_refused(merovingian::core::host_cookie(name, "v", CookieSameSite::lax, 60U)));
                    REQUIRE(is_refused(merovingian::core::host_cookie_deletion(name, CookieSameSite::lax)));
                }
            }
        }
    }

    GIVEN("values outside the cookie-octet set, or empty")
    {
        auto const values = std::array<std::string_view, 9U>{
            "", "a b", "a;b", "a,b", "\"quoted\"", "a\\b", "a\r\nSet-Cookie: x=y", "caf\xC3\xA9", "a\x7F",
        };

        WHEN("each is used to build a cookie")
        {
            THEN("each is refused")
            {
                for (auto const value : values)
                {
                    INFO("value bytes: " << value.size());
                    REQUIRE(is_refused(merovingian::core::host_cookie("__Host-s", value, CookieSameSite::strict, 60U)));
                }
            }
        }
    }

    GIVEN("lifetimes at and past the bounds and a pair at and past the size cap")
    {
        auto const name = std::string{"__Host-s"};
        auto const value_at_cap = std::string(merovingian::core::max_host_cookie_bytes - name.size(), 'v');

        WHEN("each is built")
        {
            auto const zero = merovingian::core::host_cookie(name, "v", CookieSameSite::lax, 0U);
            auto const longest = merovingian::core::host_cookie(name, "v", CookieSameSite::lax,
                                                                merovingian::core::max_host_cookie_age_seconds);
            auto const too_long = merovingian::core::host_cookie(name, "v", CookieSameSite::lax,
                                                                 merovingian::core::max_host_cookie_age_seconds + 1U);
            auto const at_cap = merovingian::core::host_cookie(name, value_at_cap, CookieSameSite::lax, 60U);
            auto const over_cap = merovingian::core::host_cookie(name, value_at_cap + "v", CookieSameSite::lax, 60U);

            THEN("zero and over-long lifetimes and an oversized pair are refused; the bounds are accepted")
            {
                REQUIRE(is_refused(zero));
                REQUIRE(text_of(longest).find("; Max-Age=34560000;") != std::string::npos);
                REQUIRE(is_refused(too_long));
                REQUIRE(std::holds_alternative<std::string>(at_cap));
                REQUIRE(is_refused(over_cap));
            }
        }
    }
}
