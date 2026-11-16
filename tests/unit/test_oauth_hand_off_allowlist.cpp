// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The shape of a hand-off redirect allowlist entry: an https origin or a bare private-use scheme, never a URL prefix
// (ADR-0774).

#include "merovingian/core/Error.hpp"
#include "merovingian/oauth/HandOffAllowlist.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <string>
#include <vector>

SCENARIO("an https origin or a bare private-use scheme is a valid hand-off allowlist entry", "[oauth][allowlist]")
{
    GIVEN("an entry of one of the two shapes")
    {
        auto const entry =
            GENERATE(as<std::string>{}, "https://app.example.com", "https://app.example.com:8443", "https://localhost",
                     "https://[::1]:8443", "io.element.app:", "com.example.app-x+y:");

        WHEN("it is checked")
        {
            auto const error = merovingian::oauth::hand_off_allowlist_entry_error(entry);

            THEN("it is accepted")
            {
                INFO(entry);
                REQUIRE_FALSE(error.has_value());
            }
        }
    }
}

SCENARIO("a hand-off allowlist entry that is a prefix, a path or another shape is refused", "[oauth][allowlist]")
{
    GIVEN("an entry that is not an https origin or a bare private-use scheme")
    {
        auto const entry =
            GENERATE(as<std::string>{},
                     // A URL prefix: a prefix match would accept https://app.example.com.evil.example.
                     "https://app.example.com/", "https://app.example.com/callback", "https://app.example.com?x=1",
                     // Not https, or no scheme at all.
                     "http://app.example.com", "app.example.com", "//app.example.com",
                     // Default port written out, upper case, userinfo, fragment.
                     "https://app.example.com:443", "https://App.example.com",
                     "IO.element.app:", "https://user@app.example.com", "https://app.example.com#x",
                     // A scheme with a general meaning, or a scheme with more than its colon.
                     "https:", "http:", "javascript:", "data:", "io.element.app:/callback", "io.element.app:x",
                     "io.element.app://host",
                     // Not a URI.
                     "", " https://app.example.com", "https://app example.com");

        WHEN("it is checked")
        {
            auto const error = merovingian::oauth::hand_off_allowlist_entry_error(entry);

            THEN("it is refused with fixed text that does not quote the entry")
            {
                INFO(entry);
                REQUIRE(error.has_value());
                CHECK(error->message().find("example.com") == std::string::npos);
            }
        }
    }
}

SCENARIO("a hand-off allowlist is bounded and holds each entry once", "[oauth][allowlist]")
{
    GIVEN("allowlists of various sizes")
    {
        auto list_of = [](int count) {
            auto out = std::vector<std::string>{};
            for (auto index = 0; index < count; ++index)
            {
                out.push_back("https://h" + std::to_string(index) + ".example.com");
            }
            return out;
        };

        WHEN("an empty list is checked")
        {
            THEN("it is accepted")
            {
                REQUIRE_FALSE(merovingian::oauth::hand_off_allowlist_error(std::vector<std::string>{}).has_value());
            }
        }

        WHEN("a list of exactly 32 entries is checked")
        {
            auto const list = list_of(32);

            THEN("it is accepted")
            {
                REQUIRE_FALSE(merovingian::oauth::hand_off_allowlist_error(list).has_value());
            }
        }

        WHEN("a list of 33 entries is checked")
        {
            auto const list = list_of(33);

            THEN("it is refused")
            {
                REQUIRE(merovingian::oauth::hand_off_allowlist_error(list).has_value());
            }
        }

        WHEN("a list names the same entry twice")
        {
            auto const list = std::vector<std::string>{"io.element.app:", "https://a.example.com", "io.element.app:"};

            THEN("it is refused")
            {
                REQUIRE(merovingian::oauth::hand_off_allowlist_error(list).has_value());
            }
        }

        WHEN("a list holds one invalid entry among valid ones")
        {
            auto const list = std::vector<std::string>{"https://a.example.com", "https://b.example.com/"};

            THEN("it is refused")
            {
                REQUIRE(merovingian::oauth::hand_off_allowlist_error(list).has_value());
            }
        }
    }
}
