// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// oauth::authorization_redirect_address, the one builder of the address an authorisation answer is sent to (spec
// "Login flow", "Callback"): the query or the fragment, and values percent-encoded so nothing but unreserved
// characters appears raw.

#include "merovingian/oauth/AuthorizationRedirect.hpp"
#include "merovingian/oauth/ParsedUri.hpp"
#include "merovingian/oauth/ResponseMode.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstddef>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

namespace
{

using merovingian::oauth::authorization_redirect_address;
using merovingian::oauth::ParsedUri;
using merovingian::oauth::RedirectParameter;
using merovingian::oauth::ResponseMode;

[[nodiscard]] auto read(std::string_view text) -> ParsedUri
{
    auto parsed = ParsedUri::read(text);
    REQUIRE(std::holds_alternative<ParsedUri>(parsed));
    return std::get<ParsedUri>(std::move(parsed));
}

constexpr auto code_and_state = std::array<RedirectParameter, 2U>{
    RedirectParameter{"code",  "c0de"},
    RedirectParameter{"state", "s1"  },
};

// Whether every byte of `text` after `from` is an unreserved character, `%`, an upper-case hex digit, `=` or `&`.
[[nodiscard]] auto only_encoded_after(std::string_view text, std::size_t from) -> bool
{
    for (auto const value : text.substr(from))
    {
        auto const allowed = (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z') ||
                             (value >= '0' && value <= '9') || value == '-' || value == '.' || value == '_' ||
                             value == '~' || value == '%' || value == '=' || value == '&';
        if (!allowed)
        {
            return false;
        }
    }
    return true;
}

} // namespace

SCENARIO("An authorisation answer goes in the query of the redirect URI", "[oauth][redirect-address]")
{
    GIVEN("redirect URIs with and without a query, a private-use scheme with and without a path, and a loopback URI")
    {
        auto const plain = read("https://app.example.com/cb");
        auto const with_query = read("https://app.example.com/cb?tab=1");
        auto const bare_question_mark = read("https://app.example.com/cb?");
        auto const private_use_path = read("com.example.app:/callback");
        auto const private_use_no_path = read("com.example.app:");
        auto const loopback = read("http://127.0.0.1:51234/cb");

        WHEN("code and state are added with the query response mode")
        {
            THEN("a new query starts with ?, an existing one continues with &, a bare ? takes them directly")
            {
                REQUIRE(authorization_redirect_address(plain, ResponseMode::query, code_and_state) ==
                        "https://app.example.com/cb?code=c0de&state=s1");
                REQUIRE(authorization_redirect_address(with_query, ResponseMode::query, code_and_state) ==
                        "https://app.example.com/cb?tab=1&code=c0de&state=s1");
                REQUIRE(authorization_redirect_address(bare_question_mark, ResponseMode::query, code_and_state) ==
                        "https://app.example.com/cb?code=c0de&state=s1");
                REQUIRE(authorization_redirect_address(private_use_path, ResponseMode::query, code_and_state) ==
                        "com.example.app:/callback?code=c0de&state=s1");
                REQUIRE(authorization_redirect_address(private_use_no_path, ResponseMode::query, code_and_state) ==
                        "com.example.app:?code=c0de&state=s1");
                REQUIRE(authorization_redirect_address(loopback, ResponseMode::query, code_and_state) ==
                        "http://127.0.0.1:51234/cb?code=c0de&state=s1");
            }
        }
    }
}

SCENARIO("An authorisation answer goes in the fragment when the response mode says so", "[oauth][redirect-address]")
{
    GIVEN("a redirect URI with a query and a private-use one")
    {
        auto const with_query = read("https://app.example.com/cb?tab=1");
        auto const private_use = read("com.example.app:/callback");

        WHEN("code and state are added with the fragment response mode")
        {
            THEN("they follow a # and the query of the URI is left as it was")
            {
                REQUIRE(authorization_redirect_address(with_query, ResponseMode::fragment, code_and_state) ==
                        "https://app.example.com/cb?tab=1#code=c0de&state=s1");
                REQUIRE(authorization_redirect_address(private_use, ResponseMode::fragment, code_and_state) ==
                        "com.example.app:/callback#code=c0de&state=s1");
            }
        }
    }
}

SCENARIO("Hostile parameter values cannot break out of their parameter", "[oauth][redirect-address][security]")
{
    GIVEN("a state holding CR, LF, &, =, #, a space, a quote, % and non-ASCII UTF-8, and a hostile name")
    {
        auto const target = read("https://app.example.com/cb");
        auto const state = std::string{"a&b=c#d e\r\nSet-Cookie: x\"%\xC3\xA9"};
        auto const parameters = std::array<RedirectParameter, 2U>{
            RedirectParameter{"state", state},
            RedirectParameter{"x&y=z", "v"  },
        };

        WHEN("the address is built in each response mode")
        {
            auto const in_query = authorization_redirect_address(target, ResponseMode::query, parameters);
            auto const in_fragment = authorization_redirect_address(target, ResponseMode::fragment, parameters);

            THEN("every byte outside the unreserved set is %XX with upper-case hex, so no CR, LF, # or space appears")
            {
                REQUIRE(in_query == "https://app.example.com/cb?state=a%26b%3Dc%23d%20e%0D%0ASet-Cookie%3A%20x%22%25"
                                    "%C3%A9&x%26y%3Dz=v");
                REQUIRE(in_fragment.ends_with(in_query.substr(in_query.find('?') + 1U)));
                REQUIRE(only_encoded_after(in_query, in_query.find('?') + 1U));
                REQUIRE(in_query.find('\r') == std::string::npos);
                REQUIRE(in_query.find('\n') == std::string::npos);
                REQUIRE(in_query.find('#') == std::string::npos);
                REQUIRE(in_fragment.find('#') == in_fragment.rfind('#'));
            }
        }

        WHEN("unreserved characters and an empty value are encoded")
        {
            THEN("they stay as they are")
            {
                REQUIRE(merovingian::oauth::percent_encode_redirect_value("AZaz09-._~") == "AZaz09-._~");
                REQUIRE(merovingian::oauth::percent_encode_redirect_value("").empty());
                REQUIRE(merovingian::oauth::percent_encode_redirect_value("+/") == "%2B%2F");
            }
        }
    }
}

SCENARIO("An answer with no parameters leaves the redirect URI unchanged", "[oauth][redirect-address][boundary]")
{
    GIVEN("a redirect URI")
    {
        auto const target = read("https://app.example.com/cb?tab=1");

        WHEN("no parameter is added")
        {
            auto const address =
                authorization_redirect_address(target, ResponseMode::fragment, std::span<RedirectParameter const>{});

            THEN("the address is the URI as registered")
            {
                REQUIRE(address == "https://app.example.com/cb?tab=1");
            }
        }
    }
}
