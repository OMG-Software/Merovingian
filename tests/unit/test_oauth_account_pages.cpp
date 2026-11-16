// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The account pages (oauth/AccountPages.hpp, ADR-0796): pure functions of their inputs. Every slot a user, a client or
// a request can fill is fed hostile text: markup, quotes, `&` and a bidirectional override character. None may inject
// markup, a value that cannot be shown is replaced by fixed text, and the addresses between the pages keep their shape.

#include "merovingian/oauth/AccountDeviceRow.hpp"
#include "merovingian/oauth/AccountPageFrame.hpp"
#include "merovingian/oauth/AccountPages.hpp"
#include "merovingian/oauth/AccountSignInInput.hpp"
#include "merovingian/oauth/HtmlText.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

namespace
{

using merovingian::oauth::AccountDeviceRow;
using merovingian::oauth::AccountPageFrame;
using merovingian::oauth::AccountSignInInput;
using merovingian::oauth::HtmlText;

// Breaks out of an attribute and an element if it is not escaped.
constexpr auto markup = std::string_view{"\"><script>alert('x')</script>&amp;"};
constexpr auto markup_escaped = std::string_view{"&quot;&gt;&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;&amp;amp;"};
// U+202E RIGHT-TO-LEFT OVERRIDE.
constexpr auto bidi_override = std::string_view{"\xE2\x80\xAE"};
constexpr auto account_url = std::string_view{"https://matrix.example.org/_merovingian/account"};
constexpr auto form_token = std::string_view{"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"};

[[nodiscard]] auto with_bidi(std::string_view text) -> std::string
{
    auto value = std::string{bidi_override};
    value.append(text);
    return value;
}

[[nodiscard]] auto contains(std::string_view haystack, std::string_view needle) -> bool
{
    return haystack.find(needle) != std::string_view::npos;
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

auto require_no_injection(std::string_view html) -> void
{
    REQUIRE_FALSE(contains(html, "<script"));
    REQUIRE_FALSE(contains(html, markup));
    REQUIRE_FALSE(contains(html, bidi_override));
}

[[nodiscard]] auto frame_with(std::string_view server, std::string_view user, std::string_view token)
    -> AccountPageFrame
{
    return AccountPageFrame{server, user, token, account_url};
}

} // namespace

SCENARIO("The account sign-in form escapes the server and the username and carries only a known action",
         "[oauth][account-page][security]")
{
    GIVEN("a server name and a username holding markup, and a device action with a device")
    {
        auto const server = std::string{"example.org"} + std::string{markup};
        auto input = AccountSignInInput{};
        input.server_name = server;
        input.username = markup;
        input.next_action = "org.matrix.device_view";
        input.next_device_id = "ABCDEFGH";

        WHEN("the form is rendered")
        {
            auto const html = merovingian::oauth::account_sign_in_page(input).render();

            THEN("both values appear escaped and the action and device ride in hidden fields")
            {
                require_no_injection(html);
                CHECK(count(html, markup_escaped) == 2U);
                CHECK(contains(html, R"(action="/_merovingian/account")"));
                CHECK(contains(html, R"(name="next_action" value="org.matrix.device_view")"));
                CHECK(contains(html, R"(name="next_device_id" value="ABCDEFGH")"));
                CHECK(contains(html, R"(name="action" value="sign_in")"));
                CHECK_FALSE(contains(html, "form_token"));
            }
        }
    }

    GIVEN("an unknown action, a device for an action that takes none, and values with an override character")
    {
        auto const server = with_bidi("example.org");
        auto const username = with_bidi("alice");
        auto unknown = AccountSignInInput{};
        unknown.server_name = "example.org";
        unknown.next_action = markup;
        unknown.next_device_id = "ABCDEFGH";
        auto profile = AccountSignInInput{};
        profile.server_name = "example.org";
        profile.next_action = "org.matrix.profile";
        profile.next_device_id = "ABCDEFGH";
        auto hidden = AccountSignInInput{};
        hidden.server_name = server;
        hidden.username = username;

        WHEN("each form is rendered")
        {
            auto const unknown_html = merovingian::oauth::account_sign_in_page(unknown).render();
            auto const profile_html = merovingian::oauth::account_sign_in_page(profile).render();
            auto const hidden_html = merovingian::oauth::account_sign_in_page(hidden).render();

            THEN("nothing unknown is carried, the device only with a device action, and the fallback text is shown")
            {
                require_no_injection(unknown_html);
                CHECK_FALSE(contains(unknown_html, "next_action"));
                CHECK_FALSE(contains(unknown_html, "next_device_id"));
                CHECK(contains(profile_html, R"(name="next_action" value="org.matrix.profile")"));
                CHECK_FALSE(contains(profile_html, "next_device_id"));
                require_no_injection(hidden_html);
                CHECK(contains(hidden_html, "Sign in with your account on this server to manage it."));
                CHECK_FALSE(contains(hidden_html, "alice"));
            }
        }
    }
}

SCENARIO("Every signed-in account page escapes the user, the server and every device field",
         "[oauth][account-page][security]")
{
    GIVEN("a frame and a device whose every client-chosen value holds markup")
    {
        auto const server = std::string{"example.org"} + std::string{markup};
        auto const user = std::string{"@alice:example.org"} + std::string{markup};
        auto const frame = frame_with(server, user, form_token);
        auto const device = AccountDeviceRow{markup, markup, true, markup};
        auto const devices = std::array{device};

        WHEN("each page is rendered")
        {
            auto const pages = std::array{
                merovingian::oauth::account_overview_page(frame, markup).render(),
                merovingian::oauth::account_devices_page(frame, devices).render(),
                merovingian::oauth::account_device_page(frame, device).render(),
                merovingian::oauth::account_device_delete_page(frame, device).render(),
                merovingian::oauth::account_unknown_device_page(frame).render(),
                merovingian::oauth::account_password_page(frame, HtmlText{"An error."}).render(),
                merovingian::oauth::account_deactivate_page(frame, std::nullopt).render(),
                merovingian::oauth::account_cross_signing_reset_page(frame).render(),
                merovingian::oauth::account_result_page(frame, HtmlText{"Done"}, HtmlText{"It was done."}).render(),
            };

            THEN("nothing is injected, every form carries the form token, and links keep their shape")
            {
                for (auto const& html : pages)
                {
                    require_no_injection(html);
                    CHECK(contains(html, markup_escaped));
                    CHECK(count(html, "<form ") == count(html, R"(name="form_token" value=")"));
                    CHECK(contains(html, std::string{R"(name="form_token" value=")"} + std::string{form_token}));
                }
                // The device link percent-encodes the device ID, so it cannot add a parameter or leave the attribute.
                CHECK(contains(pages.at(1U), "device_id=%22%3E%3Cscript%3E"));
                CHECK(contains(pages.at(3U), std::string{R"(name="device_id" value=")"} + std::string{markup_escaped}));
                CHECK(contains(pages.at(3U), R"(name="action" value="delete_device")"));
                CHECK(contains(pages.at(5U), R"(role="alert">An error.)"));
                CHECK(contains(pages.at(6U), R"(name="action" value="deactivate")"));
                CHECK(contains(pages.at(7U), R"(name="action" value="approve_cross_signing_reset")"));
            }
        }
    }
}

SCENARIO("An account page shows fixed text for a value it cannot show, and no form without a form token",
         "[oauth][account-page][security]")
{
    GIVEN("a frame and a device holding override characters, and a frame whose form token cannot be shown")
    {
        auto const user = with_bidi("@alice:example.org");
        auto const name = with_bidi("Phone");
        auto const client = with_bidi("Test App");
        auto const frame = frame_with("example.org", user, form_token);
        auto const device = AccountDeviceRow{"ABCDEFGH", name, true, client};
        auto const no_token = with_bidi("token");
        auto const tokenless = frame_with("example.org", "@alice:example.org", no_token);

        WHEN("the device page and the token-less pages are rendered")
        {
            auto const device_html = merovingian::oauth::account_device_page(frame, device).render();
            auto const overview = merovingian::oauth::account_overview_page(tokenless, std::nullopt).render();
            auto const reset = merovingian::oauth::account_cross_signing_reset_page(tokenless).render();
            auto const remove = merovingian::oauth::account_device_delete_page(tokenless, device).render();

            THEN("fixed text replaces each value, and a page with no token shows no form")
            {
                require_no_injection(device_html);
                CHECK(contains(device_html, "an account that cannot be shown"));
                CHECK(contains(device_html, "A name that cannot be shown"));
                CHECK(contains(device_html, "An application with no name"));
                for (auto const* html : {&overview, &reset, &remove})
                {
                    require_no_injection(*html);
                    CHECK_FALSE(contains(*html, "<form"));
                }
                CHECK(contains(overview, "No display name set"));
            }
        }
    }
}

SCENARIO("The account action address percent-encodes the action and the device", "[oauth][account-page]")
{
    GIVEN("a device ID that would add a parameter if copied as it is")
    {
        WHEN("addresses are built with and without a device")
        {
            auto const plain =
                merovingian::oauth::account_action_address(account_url, "org.matrix.cross_signing_reset");
            auto const device =
                merovingian::oauth::account_action_address(account_url, "org.matrix.device_view", "A&action=x#y");

            THEN("each has one action and, when given, one device_id, with nothing copied raw")
            {
                CHECK(plain == std::string{account_url} + "?action=org.matrix.cross_signing_reset");
                CHECK(device ==
                      std::string{account_url} + "?action=org.matrix.device_view&device_id=A%26action%3Dx%23y");
            }
        }
    }

    GIVEN("the six spec actions and other text")
    {
        WHEN("each is looked up")
        {
            THEN("only the six exact names are known, and only the two device actions take a device")
            {
                for (auto const action : merovingian::oauth::account_management_actions())
                {
                    CHECK(merovingian::oauth::account_management_action(action) == action);
                }
                CHECK_FALSE(merovingian::oauth::account_management_action(std::nullopt).has_value());
                CHECK_FALSE(merovingian::oauth::account_management_action("ORG.MATRIX.PROFILE").has_value());
                CHECK_FALSE(merovingian::oauth::account_management_action("org.matrix.profile ").has_value());
                CHECK_FALSE(merovingian::oauth::account_management_action("").has_value());
                CHECK(merovingian::oauth::account_action_takes_device("org.matrix.device_view"));
                CHECK(merovingian::oauth::account_action_takes_device("org.matrix.device_delete"));
                CHECK_FALSE(merovingian::oauth::account_action_takes_device("org.matrix.devices_list"));
                CHECK_FALSE(merovingian::oauth::account_action_takes_device("org.matrix.profile"));
            }
        }
    }
}
