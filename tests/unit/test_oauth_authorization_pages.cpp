// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The pages of the authorisation endpoint (oauth/AuthorizationPages.hpp, ADR-0815, ADR-0772): login, registration,
// consent, error and device (P11) pages, each a pure function of its inputs. Every slot is fed hostile text: markup,
// quotes, `&`, bidirectional override characters and a 10 KiB value. None may inject markup, and a value that cannot be
// shown is replaced by fixed text.

#include "merovingian/oauth/AccountFormInput.hpp"
#include "merovingian/oauth/AuthorizationPages.hpp"
#include "merovingian/oauth/ConsentPageInput.hpp"
#include "merovingian/oauth/DeviceConsentPageInput.hpp"
#include "merovingian/oauth/HtmlText.hpp"
#include "merovingian/oauth/ParsedUri.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

namespace
{

using merovingian::oauth::AccountFormInput;
using merovingian::oauth::ConsentPageInput;
using merovingian::oauth::HtmlText;
using merovingian::oauth::ParsedUri;

// Breaks out of an attribute and an element if it is not escaped.
constexpr auto markup = std::string_view{"\"><script>alert('x')</script>&amp;"};
constexpr auto markup_escaped = std::string_view{"&quot;&gt;&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;&amp;amp;"};
// U+202E RIGHT-TO-LEFT OVERRIDE, which can make a host read backwards.
constexpr auto bidi_override = std::string_view{"\xE2\x80\xAE"};

[[nodiscard]] auto with_bidi(std::string_view text) -> std::string
{
    auto value = std::string{bidi_override};
    value.append(text);
    return value;
}

[[nodiscard]] auto read(std::string_view text) -> ParsedUri
{
    auto parsed = ParsedUri::read(text);
    REQUIRE(std::holds_alternative<ParsedUri>(parsed));
    return std::get<ParsedUri>(std::move(parsed));
}

[[nodiscard]] auto count(std::string_view haystack, std::string_view needle) -> std::size_t
{
    auto found = std::size_t{0U};
    for (auto at = haystack.find(needle); at != std::string_view::npos; at = haystack.find(needle, at + 1U))
    {
        ++found;
    }
    return found;
}

[[nodiscard]] auto contains(std::string_view haystack, std::string_view needle) -> bool
{
    return haystack.find(needle) != std::string_view::npos;
}

// No markup a page did not write itself: no script element, no raw payload, no override character.
auto require_no_injection(std::string_view html) -> void
{
    REQUIRE_FALSE(contains(html, "<script"));
    REQUIRE_FALSE(contains(html, markup));
    REQUIRE_FALSE(contains(html, bidi_override));
}

constexpr auto pending = std::string_view{"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"};

} // namespace

SCENARIO("The login page escapes the server name and the prefilled username", "[oauth][authorize-page][security]")
{
    GIVEN("a server name and a username holding markup")
    {
        auto input = AccountFormInput{};
        auto const server = std::string{"example.org"} + std::string{markup};
        input.server_name = server;
        input.pending_id = pending;
        input.username = markup;
        input.offer_other_form = true;

        WHEN("the login page is rendered")
        {
            auto const html = merovingian::oauth::login_page(input).render();

            THEN("both appear escaped, and the form posts the pending identifier with the login action")
            {
                require_no_injection(html);
                REQUIRE(count(html, markup_escaped) == 2U);
                REQUIRE(contains(html, R"(action="/_merovingian/oauth2/authorize")"));
                REQUIRE(contains(html, std::string{R"(name="pending" value=")"} + std::string{pending} + "\""));
                REQUIRE(contains(html, R"(name="action" value="login")"));
                REQUIRE(contains(html, R"(autocomplete="username")"));
                REQUIRE(contains(
                    html, R"(type="password" id="field-password" name="password" autocomplete="current-password")"));
            }

            THEN("a second form offers registration for the same pending authorisation")
            {
                REQUIRE(count(html, "<form ") == 2U);
                REQUIRE(contains(html, R"(name="action" value="show_register")"));
                REQUIRE(count(html, std::string{R"(name="pending" value=")"} + std::string{pending}) == 2U);
            }
        }
    }
}

SCENARIO("The login page falls back to fixed text for values it cannot show", "[oauth][authorize-page][security]")
{
    GIVEN("a server name and username with a right-to-left override, and no offer of registration")
    {
        auto input = AccountFormInput{};
        auto const server = with_bidi("example.org");
        auto const username = with_bidi("alice");
        input.server_name = server;
        input.pending_id = pending;
        input.username = username;
        input.error = HtmlText{"That username and password do not match."};

        WHEN("the login page is rendered")
        {
            auto const html = merovingian::oauth::login_page(input).render();

            THEN("the server is named as this server, nothing is prefilled, and the error is shown")
            {
                require_no_injection(html);
                REQUIRE(contains(html, "Sign in with your account on this server."));
                REQUIRE_FALSE(contains(html, R"(id="field-username" name="username" autocomplete="username" value=)"));
                REQUIRE(contains(html, R"(role="alert">That username and password do not match.)"));
                REQUIRE(count(html, "<form ") == 1U);
                REQUIRE_FALSE(contains(html, "show_register"));
            }
        }
    }
}

SCENARIO("A page whose pending identifier cannot be shown holds no form", "[oauth][authorize-page][security]")
{
    GIVEN("a pending identifier with a right-to-left override")
    {
        auto const hostile_pending = with_bidi("abc");
        auto input = AccountFormInput{};
        input.server_name = "example.org";
        input.pending_id = hostile_pending;
        input.offer_other_form = true;
        auto consent = ConsentPageInput{};
        consent.pending_id = hostile_pending;
        consent.client_host = "app.example.com";
        consent.user_id = "@alice:example.org";
        consent.device_id = "DEVICEABCDEF";
        auto const target = read("https://app.example.com/cb");

        WHEN("each page is rendered")
        {
            auto const login = merovingian::oauth::login_page(input).render();
            auto const registration = merovingian::oauth::registration_page(input).render();
            auto const approval = merovingian::oauth::consent_page(consent, target).render();

            THEN("none has a form, and each says the sign-in cannot continue")
            {
                for (auto const* html : {&login, &registration, &approval})
                {
                    require_no_injection(*html);
                    REQUIRE_FALSE(contains(*html, "<form"));
                    REQUIRE(contains(*html, "This sign-in cannot continue."));
                }
            }
        }
    }

    GIVEN("a pending identifier holding markup")
    {
        auto input = AccountFormInput{};
        input.server_name = "example.org";
        input.pending_id = markup;

        WHEN("the login page is rendered")
        {
            auto const html = merovingian::oauth::login_page(input).render();

            THEN("the hidden field holds it escaped")
            {
                require_no_injection(html);
                REQUIRE(contains(html, std::string{R"(name="pending" value=")"} + std::string{markup_escaped} + "\""));
            }
        }
    }
}

SCENARIO("The registration page asks for a new password twice and a token only when one is required",
         "[oauth][authorize-page]")
{
    GIVEN("a registration form input that needs a token, and one that does not")
    {
        auto with_token = AccountFormInput{};
        with_token.server_name = "example.org";
        with_token.pending_id = pending;
        with_token.username = markup;
        with_token.registration_token_required = true;
        with_token.offer_other_form = true;
        auto without_token = with_token;
        without_token.registration_token_required = false;
        without_token.offer_other_form = false;
        without_token.notice = HtmlText{"This server does not accept new accounts."};

        WHEN("both are rendered")
        {
            auto const tokened = merovingian::oauth::registration_page(with_token).render();
            auto const plain = merovingian::oauth::registration_page(without_token).render();

            THEN("both use new-password for the two password inputs and the register action")
            {
                for (auto const* html : {&tokened, &plain})
                {
                    require_no_injection(*html);
                    REQUIRE(contains(*html, markup_escaped));
                    REQUIRE(count(*html, R"(autocomplete="new-password")") == 2U);
                    REQUIRE(contains(*html, R"(name="password_confirm")"));
                    REQUIRE(contains(*html, R"(name="action" value="register")"));
                }
            }

            THEN("only the first asks for the token and offers the switch to sign-in; the second shows the notice")
            {
                REQUIRE(contains(tokened, R"(name="registration_token")"));
                REQUIRE(contains(tokened, R"(value="show_login")"));
                REQUIRE_FALSE(contains(plain, R"(name="registration_token")"));
                REQUIRE_FALSE(contains(plain, "show_login"));
                REQUIRE(contains(plain, R"(class="notice">This server does not accept new accounts.)"));
            }
        }
    }
}

SCENARIO("The consent page escapes every client value and falls back for one it cannot show",
         "[oauth][authorize-page][consent][security]")
{
    GIVEN("a client whose name, user ID and device ID hold markup")
    {
        auto input = ConsentPageInput{};
        input.pending_id = pending;
        input.client_name = markup;
        input.client_host = "app.example.com";
        input.user_id = markup;
        input.device_id = markup;
        input.policy_uri = "https://app.example.com/policy?a=1&b=\"2\"";
        input.tos_uri = "javascript:alert(1)";
        auto const target = read("https://callback.example.com/cb");

        WHEN("the consent page is rendered")
        {
            auto const html = merovingian::oauth::consent_page(input, target).render();

            THEN("every value is escaped, the destination is the redirect host, and approve and deny are offered")
            {
                require_no_injection(html);
                REQUIRE(count(html, markup_escaped) == 3U);
                REQUIRE(contains(html, "<bdi>app.example.com</bdi>"));
                REQUIRE(contains(html, "<bdi>callback.example.com</bdi>"));
                REQUIRE(contains(html, "full access to your account"));
                REQUIRE(contains(html, R"(name="action" value="approve")"));
                REQUIRE(contains(html, R"(name="action" value="deny")"));
            }

            THEN("only an https link becomes an href")
            {
                REQUIRE_FALSE(contains(html, "javascript:"));
                REQUIRE_FALSE(contains(html, "Terms of service"));
                REQUIRE_FALSE(contains(html, "Privacy policy"));
            }
        }
    }

    GIVEN("a name with a right-to-left override, a name of 10 KiB, and no name")
    {
        auto const bidi_name = with_bidi("Element");
        auto const long_name = std::string(10U * 1024U, 'A');
        auto const target = read("com.example.app:/callback");
        auto input = ConsentPageInput{};
        input.pending_id = pending;
        input.client_host = "app.example.com";
        input.user_id = "@alice:example.org";
        input.device_id = "DEVICEABCDEF";
        input.policy_uri = "https://app.example.com/policy";
        input.replaces_existing_device = true;

        WHEN("the consent page is rendered for each")
        {
            input.client_name = bidi_name;
            auto const bidi = merovingian::oauth::consent_page(input, target).render();
            input.client_name = long_name;
            auto const long_page = merovingian::oauth::consent_page(input, target).render();
            input.client_name.reset();
            auto const unnamed = merovingian::oauth::consent_page(input, target).render();

            THEN("each shows the fixed phrase, never the raw name")
            {
                for (auto const* html : {&bidi, &long_page, &unnamed})
                {
                    require_no_injection(*html);
                    REQUIRE(contains(*html, "<bdi>An application with no name</bdi>"));
                    REQUIRE_FALSE(contains(*html, "Element"));
                    REQUIRE_FALSE(contains(*html, long_name.substr(0U, 200U)));
                }
            }

            THEN("the private-use destination is named by its scheme, the policy is linked, the replacement noticed")
            {
                REQUIRE(contains(unnamed, "<bdi>com.example.app: (an application on your device)</bdi>"));
                REQUIRE(contains(unnamed, R"(<a href="https://app.example.com/policy" rel="noopener noreferrer">)"));
                REQUIRE(contains(unnamed, "signs that session out and replaces it"));
            }
        }
    }
}

SCENARIO("The error page shows its title and message and no form", "[oauth][authorize-page]")
{
    GIVEN("a fixed title and message")
    {
        WHEN("the error page is rendered")
        {
            auto const html = merovingian::oauth::error_page(HtmlText{"Sign-in expired"},
                                                             HtmlText{"Return to the application and start again."})
                                  .render();

            THEN("it holds both and no form")
            {
                REQUIRE(contains(html, "<h1>Sign-in expired</h1>"));
                REQUIRE(contains(html, "Return to the application and start again."));
                REQUIRE_FALSE(contains(html, "<form"));
            }
        }
    }
}

SCENARIO("The device link page offers the code form and prefills only a code", "[oauth][authorize-page][device]")
{
    GIVEN("a stored user code and no code")
    {
        WHEN("the link page is rendered with each, and with an error")
        {
            auto const prefilled = merovingian::oauth::device_link_page("BCDFGHJK", std::nullopt).render();
            auto const empty = merovingian::oauth::device_link_page(std::nullopt, std::nullopt).render();
            auto const refused =
                merovingian::oauth::device_link_page(std::nullopt, HtmlText{"That code is not right."}).render();

            THEN("the form posts to the link page with the code field, shown as two groups of four when prefilled")
            {
                for (auto const* html : {&prefilled, &empty, &refused})
                {
                    REQUIRE(contains(*html, R"(action="/_merovingian/oauth2/link")"));
                    REQUIRE(contains(*html, R"(name="user_code")"));
                    REQUIRE(contains(*html, R"(autocomplete="off")"));
                    REQUIRE(count(*html, "<form ") == 1U);
                }
                REQUIRE(contains(prefilled, R"(value="BCDF-GHJK")"));
                REQUIRE_FALSE(contains(empty, "BCDF"));
                REQUIRE(contains(refused, "That code is not right."));
                REQUIRE_FALSE(contains(prefilled, "That code is not right."));
            }
        }
    }
}

SCENARIO("The device consent page warns first, escapes every value and posts allow or deny",
         "[oauth][authorize-page][device][security]")
{
    GIVEN("a client whose name, user ID and device ID hold markup")
    {
        auto input = merovingian::oauth::DeviceConsentPageInput{};
        input.pending_id = pending;
        input.user_code = "BCDFGHJK";
        input.client_name = markup;
        input.client_host = "tv.example.com";
        input.user_id = markup;
        input.device_id = markup;

        WHEN("the consent page is rendered")
        {
            auto const html = merovingian::oauth::device_consent_page(input).render();

            THEN("the warning comes before the code, and every value is escaped")
            {
                require_no_injection(html);
                REQUIRE(count(html, markup_escaped) == 3U);
                auto const warning = html.find("not this browser");
                auto const code = html.find("BCDF-GHJK");
                REQUIRE(warning != std::string::npos);
                REQUIRE(code != std::string::npos);
                REQUIRE(warning < code);
                REQUIRE(contains(html, "If someone sent you this code or link, deny."));
                REQUIRE(contains(html, "<bdi>tv.example.com</bdi>"));
                REQUIRE(contains(html, "full access to your account"));
                REQUIRE_FALSE(contains(html, "signs that session out"));
            }

            THEN("one form posts the pending identifier to the authorisation endpoint with allow and deny")
            {
                REQUIRE(count(html, "<form ") == 1U);
                REQUIRE(contains(html, R"(action="/_merovingian/oauth2/authorize")"));
                REQUIRE(contains(html, std::string{R"(name="pending" value=")"} + std::string{pending} + "\""));
                REQUIRE(contains(html, R"(name="action" value="approve")"));
                REQUIRE(contains(html, R"(name="action" value="deny")"));
            }
        }
    }

    GIVEN("a client with a bidirectional override in its name, a device the user holds, and a bad pending identifier")
    {
        auto const bidi_name = with_bidi("Television");
        auto const hostile_pending = with_bidi("abc");
        auto input = merovingian::oauth::DeviceConsentPageInput{};
        input.pending_id = hostile_pending;
        input.user_code = "BCDFGHJK";
        input.client_name = bidi_name;
        input.client_host = "tv.example.com";
        input.user_id = "@alice:example.org";
        input.device_id = "TVDEVICE";
        input.replaces_existing_device = true;

        WHEN("the consent page is rendered")
        {
            auto const html = merovingian::oauth::device_consent_page(input).render();

            THEN("the name is the fixed phrase, the replacement is noticed, and no form is offered")
            {
                require_no_injection(html);
                REQUIRE(contains(html, "<bdi>An application with no name</bdi>"));
                REQUIRE_FALSE(contains(html, "Television"));
                REQUIRE(contains(html, "signs that session out and replaces it"));
                REQUIRE_FALSE(contains(html, "<form"));
                REQUIRE(contains(html, "This sign-in cannot continue."));
            }
        }
    }
}

SCENARIO("The device answer pages send the user back to the device and hold no form", "[oauth][authorize-page][device]")
{
    GIVEN("an approval and a denial")
    {
        WHEN("both pages are rendered")
        {
            auto const approved = merovingian::oauth::device_approved_page().render();
            auto const denied = merovingian::oauth::device_denied_page().render();

            THEN("the approval says to return to the other device, and neither has a form")
            {
                REQUIRE(contains(approved, "Return to your other device"));
                REQUIRE(contains(denied, "was not let into your account"));
                REQUIRE_FALSE(contains(approved, "<form"));
                REQUIRE_FALSE(contains(denied, "<form"));
            }
        }
    }
}
