// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The legacy login hand-off's `redirectUrl` rules and its return address (oauth/HandOffRedirect.hpp), and its two
// pages (oauth/AuthorizationPages.hpp), plan P10, ADR-0802. Pure functions: no runtime.

#include "merovingian/oauth/AuthorizationPages.hpp"
#include "merovingian/oauth/HandOffRedirect.hpp"
#include "merovingian/oauth/ParsedUri.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace
{

using merovingian::oauth::hand_off_redirect_target;
using merovingian::oauth::hand_off_return_address;

[[nodiscard]] auto contains(std::string_view haystack, std::string_view needle) -> bool
{
    return haystack.find(needle) != std::string_view::npos;
}

[[nodiscard]] auto accepted(std::string_view url, std::vector<std::string> const& allowlist = {}) -> bool
{
    return hand_off_redirect_target(url, allowlist).has_value();
}

// U+202E RIGHT-TO-LEFT OVERRIDE: HtmlText refuses it, so a page holding it as the pending identifier shows no form.
constexpr auto unshowable_pending = std::string_view{"abc\xE2\x80\xAE"};
constexpr auto pending = std::string_view{"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"};

} // namespace

SCENARIO("An https address, a loopback http address and a private-use scheme are hand-off targets",
         "[oauth][hand-off-redirect]")
{
    GIVEN("an address of an accepted shape")
    {
        auto const url = GENERATE(as<std::string>{}, "https://app.example.com/cb", "https://app.example.com:8443/x?y=1",
                                  "HTTPS://App.Example.com/cb", "http://localhost:8080/cb", "http://127.0.0.1/cb",
                                  "http://[::1]:9000/", "http://LOCALHOST/cb", "io.element.app:/callback",
                                  "com.example.app://login", "Com.Example.App:/x");

        WHEN("no allowlist is configured")
        {
            THEN("it is accepted")
            {
                INFO(url);
                REQUIRE(accepted(url));
            }
        }
    }
}

SCENARIO("Any other address is refused as a hand-off target", "[oauth][hand-off-redirect][security]")
{
    GIVEN("an address of a refused shape")
    {
        auto const url = GENERATE(as<std::string>{}, "", "javascript:alert(1)", "data:text/html,x",
                                  "file:///etc/passwd", "http://app.example.com/cb", "http://10.0.0.1/cb",
                                  "http://localhost.evil.com/", "https:/no-authority", "ftp://example.com/",
                                  "myapp:/cb", "/relative/path", "https://app.example.com/cb#fragment",
                                  "https://user@app.example.com/cb", "https://app.example.com/a b");

        WHEN("it is checked")
        {
            THEN("it is refused")
            {
                INFO(url);
                REQUIRE_FALSE(accepted(url));
            }
        }
    }
}

SCENARIO("A configured allowlist limits the hand-off to its origins and schemes", "[oauth][hand-off-redirect]")
{
    GIVEN("an allowlist of one https origin and one private-use scheme")
    {
        auto const allowlist = std::vector<std::string>{"https://app.example.com", "io.element.app:"};

        WHEN("addresses are checked against it")
        {
            THEN("only a matching origin, port or scheme passes")
            {
                CHECK(accepted("https://app.example.com/cb", allowlist));
                CHECK(accepted("https://APP.example.com:443/other", allowlist));
                CHECK(accepted("IO.Element.App:/cb", allowlist));
                CHECK_FALSE(accepted("https://app.example.com:8443/cb", allowlist));
                CHECK_FALSE(accepted("https://evil.example.com/cb", allowlist));
                CHECK_FALSE(accepted("https://app.example.com.evil.com/cb", allowlist));
                CHECK_FALSE(accepted("com.example.app:/cb", allowlist));
                // A loopback address matches no entry, so an allowlist refuses it.
                CHECK_FALSE(accepted("http://localhost:8080/cb", allowlist));
            }
        }
    }
}

SCENARIO("The return address replaces every loginToken and keeps the rest", "[oauth][hand-off-redirect][security]")
{
    GIVEN("targets with and without a query")
    {
        auto const plain = hand_off_redirect_target("https://app.example.com/cb", {});
        auto const with_query = hand_off_redirect_target(
            "https://app.example.com/cb?a=1&loginToken=old&b=2&loginToken=older&loginTokenX=keep", {});
        auto const only_token = hand_off_redirect_target("io.element.app:/cb?loginToken=old", {});
        REQUIRE(plain.has_value());
        REQUIRE(with_query.has_value());
        REQUIRE(only_token.has_value());

        WHEN("a token is added")
        {
            auto const plain_address = hand_off_return_address(*plain, "tok");
            auto const query_address = hand_off_return_address(*with_query, "tok");
            auto const only_address = hand_off_return_address(*only_token, "a b&c");

            THEN("the token appears once, earlier values are gone and other parameters keep their order")
            {
                REQUIRE(plain_address == std::optional<std::string>{"https://app.example.com/cb?loginToken=tok"});
                REQUIRE(query_address == std::optional<std::string>{
                                             "https://app.example.com/cb?a=1&b=2&loginTokenX=keep&loginToken=tok"});
                // The token is percent-encoded.
                REQUIRE(only_address == std::optional<std::string>{"io.element.app:/cb?loginToken=a%20b%26c"});
            }
        }
    }
}

SCENARIO("The hand-off confirmation page names the account and the destination", "[oauth][hand-off-redirect]")
{
    GIVEN("an https target and a private-use target")
    {
        auto const web = hand_off_redirect_target("HTTPS://app.example.com/cb", {});
        auto const native = hand_off_redirect_target("io.element.app:/cb", {});
        REQUIRE(web.has_value());
        REQUIRE(native.has_value());

        WHEN("the pages are rendered")
        {
            auto const web_html = merovingian::oauth::hand_off_page(pending, "@alice:example.org", *web).render();
            auto const native_html = merovingian::oauth::hand_off_page(pending, "@alice:example.org", *native).render();
            auto const markup_html = merovingian::oauth::hand_off_page(pending, "\"><script>x</script>", *web).render();
            auto const no_form =
                merovingian::oauth::hand_off_page(unshowable_pending, "@alice:example.org", *web).render();
            auto const cancelled = merovingian::oauth::hand_off_cancelled_page().render();

            THEN("the host or the scheme is shown, the forms post to the authorisation endpoint, and markup is escaped")
            {
                CHECK(contains(web_html, "@alice:example.org"));
                CHECK(contains(web_html, "app.example.com"));
                CHECK_FALSE(contains(web_html, "HTTPS:"));
                CHECK(contains(web_html, R"(action="/_merovingian/oauth2/authorize")"));
                CHECK(contains(web_html, R"(value="approve")"));
                CHECK(contains(web_html, R"(value="deny")"));
                CHECK(contains(web_html, pending));
                CHECK(contains(native_html, "io.element.app: (an application on your device)"));
                CHECK_FALSE(contains(markup_html, "<script"));
                CHECK_FALSE(contains(no_form, "<form"));
                CHECK(contains(cancelled, "Sign-in cancelled"));
                CHECK_FALSE(contains(cancelled, "<form"));
            }
        }
    }
}
