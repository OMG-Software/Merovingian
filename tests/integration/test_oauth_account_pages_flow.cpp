// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// `GET` and `POST /_merovingian/account` through the client-server dispatcher: the sign-in form and its session
// (ADR-0796), each account management action with its effect checked in the store, the form protections (Origin, the
// cookie, the form token), the URL parameters, and the `m.oauth` stage of a replacing cross-signing upload (ADR-0797).
// No browser runs here: what a browser does with the cookie, the form or the policy is not tested.

#include "../support/CrossSigningFixture.hpp"
#include "../support/OAuthAccountPageSupport.hpp"
#include "../support/OAuthAuthorizationSupport.hpp"
#include "../support/OAuthRegistrationSupport.hpp"
#include "../support/OAuthTokenSupport.hpp"
#include "../support/RegistrationToken.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/database/OAuthStore.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/homeserver/AccountSessionStore.hpp"
#include "merovingian/homeserver/AuthService.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/CrossSigningResetApprovals.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/LocalHttpRequest.hpp"
#include "merovingian/homeserver/LocalHttpResponse.hpp"
#include "merovingian/homeserver/OAuthClock.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace
{

using namespace merovingian::tests;
namespace db = merovingian::database;
namespace hs = merovingian::homeserver;
using Fields = std::vector<std::pair<std::string, std::string>>;

constexpr auto alice_password = std::string_view{"AlicePass99!x"};
constexpr auto alice_id = std::string_view{"@alice:example.org"};
constexpr auto bob_password = std::string_view{"BobPass99!xyz"};
constexpr auto bob_id = std::string_view{"@bob:example.org"};
constexpr auto upload_path = std::string_view{"/_matrix/client/v3/keys/device_signing/upload"};
constexpr auto reset_url =
    std::string_view{"https://matrix.example.org/_merovingian/account?action=org.matrix.cross_signing_reset"};

[[nodiscard]] auto account_config(bool oauth_enabled = true) -> merovingian::config::Config
{
    auto config = oauth_registration_config(oauth_enabled);
    config.server().server_name = "example.org";
    enable_token_registration(config.security());
    return config;
}

// alice and bob, and a registered web client named "Test App".
struct Fixture final
{
    hs::ClientServerStartResult started;
    std::string client_id;
};

[[nodiscard]] auto make_fixture(bool oauth_enabled = true) -> Fixture
{
    auto started = hs::start_client_server(account_config(oauth_enabled));
    REQUIRE(started.started);
    auto& homeserver = started.runtime.homeserver;
    REQUIRE(hs::register_local_user(homeserver, "alice", alice_password, std::string{registration_token}).ok);
    REQUIRE(hs::register_local_user(homeserver, "bob", bob_password, std::string{registration_token}).ok);
    auto client_id = std::string{};
    if (oauth_enabled)
    {
        client_id = register_oauth_web_client(
            started.runtime, R"(,"client_name":"Test App","grant_types":["authorization_code","refresh_token"])");
        REQUIRE_FALSE(client_id.empty());
    }
    return {std::move(started), std::move(client_id)};
}

[[nodiscard]] auto send(hs::ClientServerRuntime& rt, std::string method, std::string target, std::string token,
                        std::string body = {}) -> hs::LocalHttpResponse
{
    return hs::handle_client_server_request(rt,
                                            {std::move(method), std::move(target), std::move(token), std::move(body)},
                                            /*can_wait=*/false)
        .response;
}

[[nodiscard]] auto contains(std::string_view text, std::string_view part) -> bool
{
    return text.find(part) != std::string_view::npos;
}

[[nodiscard]] auto has_header(hs::LocalHttpResponse const& response, std::string_view prefix) -> bool
{
    return std::ranges::any_of(response.headers, [prefix](auto const& header) {
        return header.first.starts_with(prefix);
    });
}

[[nodiscard]] auto member(hs::LocalHttpResponse const& response, std::string_view name) -> std::string
{
    auto const body = parse_object(response.body);
    auto const* value = string_member(body, name);
    return value == nullptr ? std::string{} : *value;
}

[[nodiscard]] auto password_login(hs::ClientServerRuntime& rt, std::string_view user, std::string_view password,
                                  std::string_view device_id) -> std::string
{
    auto const response = send(rt, "POST", "/_matrix/client/v3/login", {},
                               R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":")" +
                                   std::string{user} + R"("},"password":")" + std::string{password} +
                                   R"(","device_id":")" + std::string{device_id} + R"("})");
    return response.status == 200U ? member(response, "access_token") : std::string{};
}

[[nodiscard]] auto whoami_status(hs::ClientServerRuntime& rt, std::string const& token) -> std::uint16_t
{
    return static_cast<std::uint16_t>(send(rt, "GET", "/_matrix/client/v3/account/whoami", token).status);
}

[[nodiscard]] auto holds_device(hs::ClientServerRuntime const& rt, std::string_view user, std::string_view device)
    -> bool
{
    return db::has_user_device(rt.homeserver.database.persistent_store, user, device);
}

[[nodiscard]] auto audit_count(hs::ClientServerRuntime const& rt, std::string_view event_type) -> std::size_t
{
    return static_cast<std::size_t>(std::ranges::count_if(rt.homeserver.database.audit_events, [&](auto const& event) {
        return event.event_type == event_type;
    }));
}

// A form of a signed-in page: `action` and the session's form token, with `extra` fields.
[[nodiscard]] auto session_form(AccountSignedIn const& signed_in, std::string_view action, Fields extra = {}) -> Fields
{
    extra.emplace_back("form_token", signed_in.form_token);
    extra.emplace_back("action", std::string{action});
    return extra;
}

[[nodiscard]] auto approval_held(hs::ClientServerRuntime& rt, std::string_view user) -> bool
{
    return rt.homeserver.cross_signing_reset_approvals.holds(user, hs::oauth_wall_clock_ms());
}

} // namespace

SCENARIO("A browser signs in to the account pages and gets a short session of its own",
         "[integration][oauth][oauth-account]")
{
    GIVEN("alice and a browser with no session")
    {
        auto fixture = make_fixture();
        auto& rt = fixture.started.runtime;

        WHEN("it opens the page and signs in")
        {
            auto const first = get_account(rt, {});
            auto const signed_in = account_sign_in(rt, "alice", alice_password);
            auto const overview = get_account(rt, {}, signed_in.browser);

            THEN("the sign-in form, then a 303 setting a strict host cookie, then the overview naming alice")
            {
                REQUIRE(first.status == 200U);
                CHECK(first.page);
                CHECK(contains(first.body, "Sign in to manage your account"));
                CHECK_FALSE(has_header(first, "Access-Control-"));
                CHECK(response_header(first, "Cache-Control") == "no-store");
                CHECK(contains(response_header(first, "Content-Security-Policy"), "form-action 'self'"));

                REQUIRE(signed_in.sign_in.status == 303U);
                CHECK(response_header(signed_in.sign_in, "Location") == oauth_account_url);
                CHECK_FALSE(has_header(signed_in.sign_in, "Access-Control-"));
                auto const set_cookie = response_header(signed_in.sign_in, "Set-Cookie");
                CHECK(set_cookie.starts_with("__Host-mv-account="));
                CHECK(contains(set_cookie, "; Secure"));
                CHECK(contains(set_cookie, "; HttpOnly"));
                CHECK(contains(set_cookie, "SameSite=Strict"));
                CHECK(contains(set_cookie, "Max-Age=900"));
                CHECK(contains(set_cookie, "Path=/"));
                REQUIRE(signed_in.browser.cookie.size() == 64U);

                REQUIRE(overview.status == 200U);
                CHECK(contains(overview.body, "@alice:example.org"));
                CHECK_FALSE(has_header(overview, "Access-Control-"));
                REQUIRE(signed_in.form_token.size() == 64U);
                CHECK(signed_in.form_token != signed_in.browser.cookie);
                CHECK(rt.homeserver.account_sessions.live_count_for_user(alice_id, hs::oauth_wall_clock_ms()) == 1U);
            }
        }
    }
}

SCENARIO("A wrong password on the account page shares the login throttle with POST /login",
         "[integration][oauth][oauth-account]")
{
    GIVEN("alice")
    {
        auto fixture = make_fixture();
        auto& rt = fixture.started.runtime;

        WHEN("wrong passwords are tried until the page throttles, then POST /login is tried from the same address")
        {
            auto const first = account_sign_in(rt, "alice", "WrongPass99!x");
            auto last = first.sign_in;
            for (auto attempt = 0; attempt < 5; ++attempt)
            {
                last = account_sign_in(rt, "alice", "WrongPass99!x").sign_in;
            }
            auto legacy_request = hs::LocalHttpRequest{
                "POST",
                "/_matrix/client/v3/login",
                {},
                R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"alice"},"password":"AlicePass99!x"})"};
            legacy_request.remote_addr = AccountBrowser{}.remote_addr;
            legacy_request.headers.push_back({"Content-Type", "application/json"});
            auto const legacy = hs::handle_client_server_request(rt, legacy_request, false).response;

            THEN("the first is a 401 form keeping no password, the last a 429, and /login is throttled too")
            {
                CHECK(first.sign_in.status == 401U);
                CHECK(contains(first.sign_in.body, "do not match an account"));
                CHECK_FALSE(contains(first.sign_in.body, "WrongPass99!x"));
                CHECK(first.browser.cookie.empty());
                CHECK(last.status == 429U);
                CHECK_FALSE(response_header(last, "Retry-After").empty());
                CHECK(legacy.status == 429U);
            }
        }
    }
}

SCENARIO("The account page carries action and device_id through the sign-in and never shows the query unescaped",
         "[integration][oauth][oauth-account]")
{
    GIVEN("alice signed in to a client through OAuth, so she holds device OAUTHDEV01")
    {
        auto fixture = make_fixture();
        auto& rt = fixture.started.runtime;
        REQUIRE(oauth_sign_in(rt, fixture.client_id, "alice", alice_password).ok);

        WHEN("a device page is opened with no session, signed in to, and hostile queries are sent")
        {
            auto const form = get_account(rt, "action=org.matrix.device_view&device_id=OAUTHDEV01");
            auto const profile_form = get_account(rt, "action=org.matrix.profile&device_id=OAUTHDEV01");
            auto const signed_in = account_sign_in(rt, "alice", alice_password,
                                                   {
                                                       {"next_action",    "org.matrix.device_view"},
                                                       {"next_device_id", "OAUTHDEV01"            },
            });
            auto const device_page =
                get_account(rt, "action=org.matrix.device_view&device_id=OAUTHDEV01", signed_in.browser);
            auto const hostile_form =
                get_account(rt, "action=%3Cscript%3Ealert(1)%3C%2Fscript%3E&device_id=%22%3E%3Cb%3E");
            auto const hostile_signed_in = get_account(
                rt, "action=org.matrix.device_view&device_id=%3Cscript%3Ealert(1)%3C%2Fscript%3E", signed_in.browser);
            auto const unknown_action = get_account(rt, "action=org.matrix.nonsense", signed_in.browser);

            THEN("the form carries both, the sign-in lands on that page, and nothing hostile is reflected")
            {
                REQUIRE(form.status == 200U);
                CHECK(contains(form.body, R"(name="next_action" value="org.matrix.device_view")"));
                CHECK(contains(form.body, R"(name="next_device_id" value="OAUTHDEV01")"));
                CHECK(contains(profile_form.body, R"(name="next_action" value="org.matrix.profile")"));
                CHECK_FALSE(contains(profile_form.body, "next_device_id"));

                REQUIRE(signed_in.sign_in.status == 303U);
                CHECK(response_header(signed_in.sign_in, "Location") ==
                      std::string{oauth_account_url} + "?action=org.matrix.device_view&device_id=OAUTHDEV01");
                REQUIRE(device_page.status == 200U);
                CHECK(contains(device_page.body, "OAUTHDEV01"));
                CHECK(contains(device_page.body, "Test App"));

                CHECK(hostile_form.status == 200U);
                CHECK_FALSE(contains(hostile_form.body, "<script>"));
                CHECK_FALSE(contains(hostile_form.body, "<b>"));
                CHECK_FALSE(contains(hostile_form.body, "next_action"));
                CHECK(hostile_signed_in.status == 200U);
                CHECK_FALSE(contains(hostile_signed_in.body, "<script>"));
                CHECK(unknown_action.status == 200U);
                CHECK(contains(unknown_action.body, "Your account"));
            }
        }
    }
}

SCENARIO("A form post of the account page needs this server's origin, the cookie and the session's form token",
         "[integration][oauth][oauth-account]")
{
    GIVEN("alice and bob, each signed in to the account page")
    {
        auto fixture = make_fixture();
        auto& rt = fixture.started.runtime;
        auto const alice = account_sign_in(rt, "alice", alice_password);
        auto const bob = account_sign_in(rt, "bob", bob_password);
        REQUIRE_FALSE(alice.browser.cookie.empty());
        REQUIRE_FALSE(bob.form_token.empty());

        WHEN("alice's approval is posted without the cookie, with bob's token, and from other origins")
        {
            auto const approve = session_form(alice, "approve_cross_signing_reset");
            auto without_cookie = alice.browser;
            without_cookie.cookie.clear();
            auto const no_cookie = post_account(rt, approve, without_cookie);
            auto const foreign_token =
                post_account(rt, session_form(bob, "approve_cross_signing_reset"), alice.browser);
            auto const no_token = post_account(rt,
                                               {
                                                   {"action", "approve_cross_signing_reset"}
            },
                                               alice.browser);
            auto other_origin = alice.browser;
            other_origin.origin = "https://evil.example";
            auto const evil = post_account(rt, approve, other_origin);
            other_origin.origin = "null";
            auto const null_origin = post_account(rt, approve, other_origin);
            other_origin.origin.reset();
            auto const no_origin = post_account(rt, approve, other_origin);
            auto cross_site = alice.browser;
            cross_site.sec_fetch_site = "cross-site";
            auto const cross = post_account(rt, approve, cross_site);
            auto const held_before = approval_held(rt, alice_id);
            auto const accepted = post_account(rt, approve, alice.browser);

            THEN("every one of them is refused and records nothing; the real form is accepted")
            {
                CHECK(no_cookie.status == 403U);
                CHECK(foreign_token.status == 403U);
                CHECK(no_token.status == 403U);
                CHECK(evil.status == 403U);
                CHECK(null_origin.status == 403U);
                CHECK(no_origin.status == 403U);
                CHECK(cross.status == 403U);
                CHECK_FALSE(held_before);
                CHECK_FALSE(approval_held(rt, bob_id));
                CHECK(accepted.status == 200U);
                CHECK(approval_held(rt, alice_id));
                CHECK(audit_count(rt, "cross_signing.reset_approved") == 1U);
            }
        }
    }
}

SCENARIO("An account-page session ends after 15 minutes and on sign-out", "[integration][oauth][oauth-account]")
{
    GIVEN("alice")
    {
        auto fixture = make_fixture();
        auto& rt = fixture.started.runtime;
        auto const now = hs::oauth_wall_clock_ms();
        auto& sessions = rt.homeserver.account_sessions;
        // Driven through the store with a time, not a clock: one session started just over, one just under 15 minutes
        // ago.
        auto const expired = sessions.create(alice_id, now - hs::AccountSessionStore::lifetime_ms);
        auto const live = sessions.create(alice_id, now - hs::AccountSessionStore::lifetime_ms + 60'000U);
        REQUIRE(std::holds_alternative<std::string>(expired));
        REQUIRE(std::holds_alternative<std::string>(live));

        WHEN("each is used, and a signed-in browser signs out")
        {
            auto old_browser = AccountBrowser{};
            old_browser.cookie = std::get<std::string>(expired);
            auto const old_page = get_account(rt, {}, old_browser);
            auto live_browser = AccountBrowser{};
            live_browser.cookie = std::get<std::string>(live);
            auto const live_page = get_account(rt, {}, live_browser);
            auto const signed_in = account_sign_in(rt, "alice", alice_password);
            auto const sign_out = post_account(rt, session_form(signed_in, "sign_out"), signed_in.browser);
            auto const after = get_account(rt, {}, signed_in.browser);

            THEN("the expired one shows the sign-in form and deletes the cookie; sign-out ends the session")
            {
                CHECK(old_page.status == 200U);
                CHECK(contains(old_page.body, "Sign in to manage your account"));
                CHECK(contains(response_header(old_page, "Set-Cookie"), "Max-Age=0"));
                CHECK(live_page.status == 200U);
                CHECK(contains(live_page.body, "@alice:example.org"));
                CHECK(sign_out.status == 200U);
                CHECK(contains(response_header(sign_out, "Set-Cookie"), "Max-Age=0"));
                CHECK(contains(after.body, "Sign in to manage your account"));
            }
        }
    }
}

SCENARIO("The account page lists and signs out only the user's own devices, as DELETE /devices does",
         "[integration][oauth][oauth-account]")
{
    GIVEN("alice with an OAuth device and a password device, bob with a device, and alice on the account page")
    {
        auto fixture = make_fixture();
        auto& rt = fixture.started.runtime;
        auto const oauth = oauth_sign_in(rt, fixture.client_id, "alice", alice_password);
        REQUIRE(oauth.ok);
        REQUIRE_FALSE(password_login(rt, "alice", alice_password, "LEGACYDEV").empty());
        auto const bob_token = password_login(rt, "bob", bob_password, "BOBDEV");
        REQUIRE_FALSE(bob_token.empty());
        auto const alice = account_sign_in(rt, "alice", alice_password);
        REQUIRE_FALSE(alice.form_token.empty());
        auto const deleted_before = audit_count(rt, "device.deleted");

        WHEN("the pages are read and devices are signed out")
        {
            auto const list = get_account(rt, "action=org.matrix.devices_list", alice.browser);
            auto const bobs = get_account(rt, "action=org.matrix.device_view&device_id=BOBDEV", alice.browser);
            auto const unknown = get_account(rt, "action=org.matrix.device_view&device_id=NOSUCHDEV", alice.browser);
            auto const confirm = get_account(rt, "action=org.matrix.device_delete&device_id=OAUTHDEV01", alice.browser);
            auto const delete_bobs = post_account(rt,
                                                  session_form(alice, "delete_device",
                                                               {
                                                                   {"device_id", "BOBDEV"}
            }),
                                                  alice.browser);
            auto const delete_unknown = post_account(rt,
                                                     session_form(alice, "delete_device",
                                                                  {
                                                                      {"device_id", "NOSUCHDEV"}
            }),
                                                     alice.browser);
            auto const delete_own = post_account(rt,
                                                 session_form(alice, "delete_device",
                                                              {
                                                                  {"device_id", "OAUTHDEV01"}
            }),
                                                 alice.browser);

            THEN("another user's device is the unknown-device page, and alice's device goes with its session")
            {
                REQUIRE(list.status == 200U);
                CHECK(contains(list.body, "OAUTHDEV01"));
                CHECK(contains(list.body, "LEGACYDEV"));
                CHECK(contains(list.body, "Test App"));
                CHECK_FALSE(contains(list.body, "BOBDEV"));
                CHECK(bobs.status == 404U);
                CHECK(unknown.status == 404U);
                CHECK(bobs.body == unknown.body);
                CHECK(confirm.status == 200U);
                CHECK(contains(confirm.body, "Sign out this device"));

                CHECK(delete_bobs.status == 404U);
                CHECK(delete_unknown.status == 404U);
                CHECK(delete_bobs.body == delete_unknown.body);
                CHECK(holds_device(rt, bob_id, "BOBDEV"));
                CHECK(whoami_status(rt, bob_token) == 200U);

                CHECK(delete_own.status == 200U);
                CHECK_FALSE(holds_device(rt, alice_id, "OAUTHDEV01"));
                CHECK(db::find_oauth_session(rt.homeserver.database.persistent_store, alice_id, "OAUTHDEV01") ==
                      nullptr);
                CHECK(whoami_status(rt, oauth.access_token) == 401U);
                CHECK(holds_device(rt, alice_id, "LEGACYDEV"));
                CHECK(audit_count(rt, "device.deleted") == deleted_before + 1U);
            }
        }
    }
}

SCENARIO("A password change on the account page signs out every session and keeps the devices",
         "[integration][oauth][oauth-account]")
{
    GIVEN("alice with an OAuth session, a password session and two account-page sessions")
    {
        auto fixture = make_fixture();
        auto& rt = fixture.started.runtime;
        auto const oauth = oauth_sign_in(rt, fixture.client_id, "alice", alice_password);
        REQUIRE(oauth.ok);
        auto const legacy_token = password_login(rt, "alice", alice_password, "LEGACYDEV");
        REQUIRE_FALSE(legacy_token.empty());
        auto const other_page = account_sign_in(rt, "alice", alice_password);
        auto const alice = account_sign_in(rt, "alice", alice_password);
        REQUIRE_FALSE(alice.form_token.empty());
        auto const changed_before = audit_count(rt, "auth.password_changed");

        WHEN("a wrong current password and a mismatch are sent, then a real change")
        {
            auto const wrong = post_account(rt,
                                            session_form(alice, "change_password",
                                                         {
                                                             {"current_password",     "WrongPass99!x"   },
                                                             {"new_password",         "NewAlicePass77!z"},
                                                             {"new_password_confirm", "NewAlicePass77!z"},
            }),
                                            alice.browser);
            auto const mismatch = post_account(rt,
                                               session_form(alice, "change_password",
                                                            {
                                                                {"current_password",     std::string{alice_password}},
                                                                {"new_password",         "NewAlicePass77!z"         },
                                                                {"new_password_confirm", "NewAlicePass77!y"         },
            }),
                                               alice.browser);
            auto const tokens_after_refusals = whoami_status(rt, legacy_token);
            auto const changed = post_account(rt,
                                              session_form(alice, "change_password",
                                                           {
                                                               {"current_password",     std::string{alice_password}},
                                                               {"new_password",         "NewAlicePass77!z"         },
                                                               {"new_password_confirm", "NewAlicePass77!z"         },
            }),
                                              alice.browser);

            THEN("the refusals change nothing; the change ends every session and keeps every device")
            {
                CHECK(wrong.status == 401U);
                CHECK_FALSE(contains(wrong.body, "WrongPass99!x"));
                CHECK(mismatch.status == 400U);
                CHECK(tokens_after_refusals == 200U);

                REQUIRE(changed.status == 200U);
                CHECK(contains(response_header(changed, "Set-Cookie"), "Max-Age=0"));
                CHECK(whoami_status(rt, legacy_token) == 401U);
                CHECK(whoami_status(rt, oauth.access_token) == 401U);
                CHECK(holds_device(rt, alice_id, "LEGACYDEV"));
                CHECK(holds_device(rt, alice_id, "OAUTHDEV01"));
                CHECK(rt.homeserver.account_sessions.live_count_for_user(alice_id, hs::oauth_wall_clock_ms()) == 0U);
                CHECK(contains(get_account(rt, {}, other_page.browser).body, "Sign in to manage your account"));
                CHECK(audit_count(rt, "auth.password_changed") == changed_before + 1U);
                CHECK(password_login(rt, "alice", alice_password, "AGAIN").empty());
                CHECK_FALSE(password_login(rt, "alice", "NewAlicePass77!z", "AGAIN").empty());
            }
        }
    }
}

SCENARIO("Deactivation on the account page asks for the password and deactivates as the client API does",
         "[integration][oauth][oauth-account]")
{
    GIVEN("alice with a password session and two account-page sessions")
    {
        auto fixture = make_fixture();
        auto& rt = fixture.started.runtime;
        auto const legacy_token = password_login(rt, "alice", alice_password, "LEGACYDEV");
        REQUIRE_FALSE(legacy_token.empty());
        auto const other_page = account_sign_in(rt, "alice", alice_password);
        auto const alice = account_sign_in(rt, "alice", alice_password);
        REQUIRE_FALSE(alice.form_token.empty());

        WHEN("a wrong password is sent, then the right one")
        {
            auto const wrong = post_account(rt,
                                            session_form(alice, "deactivate",
                                                         {
                                                             {"password", "WrongPass99!x"}
            }),
                                            alice.browser);
            auto const still_active = whoami_status(rt, legacy_token);
            auto const done = post_account(rt,
                                           session_form(alice, "deactivate",
                                                        {
                                                            {"password", std::string{alice_password}}
            }),
                                           alice.browser);

            THEN("the wrong one changes nothing; the right one closes the account and every session")
            {
                CHECK(wrong.status == 401U);
                CHECK(still_active == 200U);
                REQUIRE(done.status == 200U);
                CHECK(contains(response_header(done, "Set-Cookie"), "Max-Age=0"));
                CHECK(whoami_status(rt, legacy_token) == 401U);
                CHECK(audit_count(rt, "auth.account_deactivated") == 1U);
                CHECK(password_login(rt, "alice", alice_password, "AGAIN").empty());
                CHECK(contains(get_account(rt, {}, other_page.browser).body, "Sign in to manage your account"));
                // Deactivation replaces the password hash, so the old password no longer verifies: the page answers
                // as for any wrong password and does not say the account was closed.
                CHECK(account_sign_in(rt, "alice", alice_password).sign_in.status == 401U);
            }
        }
    }
}

SCENARIO("The account page is not served with OAuth off, and refuses other methods",
         "[integration][oauth][oauth-account]")
{
    GIVEN("a server with the OAuth 2.0 API off, and one with it on")
    {
        auto off = make_fixture(false);
        auto on = make_fixture(true);

        WHEN("the page is asked for")
        {
            auto const get_off = get_account(off.started.runtime, {});
            auto const post_off = post_account(off.started.runtime,
                                               {
                                                   {"action", "sign_in"}
            },
                                               AccountBrowser{});
            auto const put_on = account_request(on.started.runtime, "PUT", std::string{oauth_account_path}, {}, {});

            THEN("OAuth off is 404 M_UNRECOGNIZED for every method; another method is 405 with OAuth on")
            {
                CHECK(get_off.status == 404U);
                CHECK(member(get_off, "errcode") == "M_UNRECOGNIZED");
                CHECK(post_off.status == 404U);
                CHECK(put_on.status == 405U);
            }
        }
    }
}

SCENARIO("An OAuth session replaces its cross-signing keys through the m.oauth stage and one approval",
         "[integration][oauth][oauth-account][oauth-uia]")
{
    GIVEN("alice signed in through OAuth with her first cross-signing keys, and on the account page")
    {
        auto fixture = make_fixture();
        auto& rt = fixture.started.runtime;
        auto const oauth = oauth_sign_in(rt, fixture.client_id, "alice", alice_password);
        REQUIRE(oauth.ok);
        auto const upload = [&](std::string const& token, std::string const& members) {
            return send(rt, "POST", std::string{upload_path}, token, "{" + members + "}");
        };
        auto const with_auth = [](std::string const& members, std::string const& auth) {
            return members + R"(,"auth":)" + auth;
        };
        auto const first = make_cross_signing_set(std::string{alice_id});
        REQUIRE(upload(oauth.access_token, first.selected_members(true, true, true)).status == 200U);
        auto const alice = account_sign_in(rt, "alice", alice_password);
        REQUIRE_FALSE(alice.form_token.empty());
        auto const approve = [&]() {
            return post_account(rt, session_form(alice, "approve_cross_signing_reset"), alice.browser).status;
        };

        WHEN("the same keys are sent again, then replacement keys, before and after the approval")
        {
            auto const repeat = upload(oauth.access_token, first.selected_members(true, true, true));
            auto const replacement = make_cross_signing_set(std::string{alice_id});
            auto const challenge = upload(oauth.access_token, replacement.master_member());
            auto const session = member(challenge, "session");
            auto const session_auth = R"({"session":")" + session + R"("})";
            auto const before_approval =
                upload(oauth.access_token, with_auth(replacement.master_member(), session_auth));
            auto const approved = approve();
            auto const accepted = upload(oauth.access_token, with_auth(replacement.master_member(), session_auth));
            auto const another = make_cross_signing_set(std::string{alice_id});
            auto const second = upload(oauth.access_token, with_auth(another.master_member(), session_auth));

            THEN("the repeat needs nothing; the replacement is asked for m.oauth and accepted once after approval")
            {
                CHECK(repeat.status == 200U);
                REQUIRE(challenge.status == 401U);
                CHECK(contains(challenge.body,
                               R"("flows":[{"stages":["m.oauth"]},{"stages":["org.matrix.cross_signing_reset"]}])"));
                CHECK(contains(challenge.body, std::string{R"("params":{"m.oauth":{"url":")"} + std::string{reset_url} +
                                                   R"("},"org.matrix.cross_signing_reset":{"url":")" +
                                                   std::string{reset_url} + R"("}})"));
                REQUIRE_FALSE(session.empty());
                CHECK(before_approval.status == 401U);
                CHECK(member(before_approval, "session") == session);
                CHECK(approved == 200U);
                CHECK(accepted.status == 200U);
                CHECK_FALSE(approval_held(rt, alice_id));
                CHECK(audit_count(rt, "cross_signing.reset_approved") == 1U);
                CHECK(audit_count(rt, "cross_signing.reset_used") == 1U);
                CHECK(second.status == 401U);
                CHECK(contains(second.body, "m.oauth"));
            }
        }
    }
}

SCENARIO("A client polling the replacing upload with no auth holds one session and succeeds once after approval",
         "[integration][oauth][oauth-account][oauth-uia]")
{
    GIVEN("alice signed in through OAuth with her first cross-signing keys, and on the account page")
    {
        auto fixture = make_fixture();
        auto& rt = fixture.started.runtime;
        auto const oauth = oauth_sign_in(rt, fixture.client_id, "alice", alice_password);
        REQUIRE(oauth.ok);
        auto const upload = [&](std::string const& members) {
            return send(rt, "POST", std::string{upload_path}, oauth.access_token, "{" + members + "}");
        };
        REQUIRE(upload(make_cross_signing_set(std::string{alice_id}).selected_members(true, true, true)).status ==
                200U);
        auto const alice = account_sign_in(rt, "alice", alice_password);
        REQUIRE_FALSE(alice.form_token.empty());
        auto const approve = [&]() {
            return post_account(rt, session_form(alice, "approve_cross_signing_reset"), alice.browser).status;
        };
        auto const reset_sessions = [&]() {
            return std::ranges::count_if(rt.uia_sessions, [](auto const& session) {
                return session.owner == alice_id && session.purpose == "cross_signing_reset";
            });
        };
        auto const replacement = make_cross_signing_set(std::string{alice_id}).master_member();

        WHEN("the same replacing upload is sent sixty times with no auth, then once more after the approval")
        {
            auto statuses = std::vector<std::uint16_t>{};
            auto session_ids = std::vector<std::string>{};
            for (auto poll = 0; poll < 60; ++poll)
            {
                auto const answer = upload(replacement);
                statuses.push_back(static_cast<std::uint16_t>(answer.status));
                session_ids.push_back(member(answer, "session"));
            }
            auto const sessions_before_approval = reset_sessions();
            auto const approved = approve();
            auto const accepted = upload(replacement);
            auto const after = upload(make_cross_signing_set(std::string{alice_id}).master_member());

            THEN("every poll is the challenge naming one session; the poll after the approval stores the keys once")
            {
                CHECK(std::ranges::all_of(statuses, [](std::uint16_t status) {
                    return status == 401U;
                }));
                REQUIRE_FALSE(session_ids.front().empty());
                CHECK(std::ranges::all_of(session_ids, [&](std::string const& id) {
                    return id == session_ids.front();
                }));
                CHECK(sessions_before_approval == 1);
                CHECK(approved == 200U);
                CHECK(accepted.status == 200U);
                CHECK_FALSE(approval_held(rt, alice_id));
                CHECK(audit_count(rt, "cross_signing.reset_used") == 1U);
                CHECK(after.status == 401U);
                CHECK(member(after, "session") == session_ids.front());
            }
        }

        WHEN("after an approval, the retry carries an auth dict without a session, or the pre-standard stage name")
        {
            REQUIRE(approve() == 200U);
            auto const no_session = upload(replacement + R"(,"auth":{"type":"m.oauth"})");
            auto const session =
                member(upload(make_cross_signing_set(std::string{alice_id}).master_member()), "session");
            REQUIRE(approve() == 200U);
            auto const unstable =
                upload(make_cross_signing_set(std::string{alice_id}).master_member() +
                       R"(,"auth":{"type":"org.matrix.cross_signing_reset","session":")" + session + R"("})");

            THEN("both complete the stage, each spending one approval")
            {
                CHECK(no_session.status == 200U);
                REQUIRE_FALSE(session.empty());
                CHECK(unstable.status == 200U);
                CHECK_FALSE(approval_held(rt, alice_id));
                CHECK(audit_count(rt, "cross_signing.reset_used") == 2U);
            }
        }

        WHEN("after an approval, the retry names a session this server did not issue, or sends auth that is no object")
        {
            REQUIRE(approve() == 200U);
            auto const foreign = upload(replacement + R"(,"auth":{"session":"not-a-session-of-ours"})");
            auto const not_object = upload(replacement + R"(,"auth":"m.oauth")");

            THEN("each gets the challenge and the approval stays")
            {
                CHECK(foreign.status == 401U);
                CHECK(contains(foreign.body, "m.oauth"));
                CHECK(not_object.status == 401U);
                CHECK(approval_held(rt, alice_id));
                CHECK(audit_count(rt, "cross_signing.reset_used") == 0U);
            }
        }
    }
}

SCENARIO("A cross-signing reset approval is not usable expired, by a refused upload, by a password stage or by a "
         "password session",
         "[integration][oauth][oauth-account][oauth-uia]")
{
    GIVEN("alice signed in through OAuth and with a password, holding cross-signing keys, and a challenge session")
    {
        auto fixture = make_fixture();
        auto& rt = fixture.started.runtime;
        auto const oauth = oauth_sign_in(rt, fixture.client_id, "alice", alice_password);
        REQUIRE(oauth.ok);
        auto const legacy_token = password_login(rt, "alice", alice_password, "LEGACYDEV");
        REQUIRE_FALSE(legacy_token.empty());
        auto const upload = [&](std::string const& token, std::string const& members) {
            return send(rt, "POST", std::string{upload_path}, token, "{" + members + "}");
        };
        REQUIRE(
            upload(oauth.access_token, make_cross_signing_set(std::string{alice_id}).selected_members(true, true, true))
                .status == 200U);
        auto const replacement = make_cross_signing_set(std::string{alice_id});
        auto const session = member(upload(oauth.access_token, replacement.master_member()), "session");
        REQUIRE_FALSE(session.empty());
        auto const session_auth = R"(,"auth":{"session":")" + session + R"("})";
        auto& approvals = rt.homeserver.cross_signing_reset_approvals;
        auto const now = hs::oauth_wall_clock_ms();

        WHEN("each misuse is tried")
        {
            // An approval granted just over ten minutes ago.
            REQUIRE(approvals.approve(alice_id, now - hs::CrossSigningResetApprovals::lifetime_ms));
            auto const expired = upload(oauth.access_token, replacement.master_member() + session_auth);
            // A live approval, then an upload that takes it and is refused (bob's key) before anything is stored.
            REQUIRE(approvals.approve(alice_id, now));
            auto const refused =
                upload(oauth.access_token, make_cross_signing_set(std::string{bob_id}).master_member() + session_auth);
            auto const held_after_refusal = approval_held(rt, alice_id);
            auto const password_stage =
                upload(oauth.access_token, replacement.master_member() +
                                               R"(,"auth":{"type":"m.login.password",)"
                                               R"("identifier":{"type":"m.id.user","user":"alice"},)"
                                               R"("password":"AlicePass99!x","session":")" +
                                               session + R"("})");
            auto const held_after_password = approval_held(rt, alice_id);
            auto const legacy = upload(legacy_token, replacement.master_member() + session_auth);
            auto const held_after_legacy = approval_held(rt, alice_id);

            THEN("each is refused, and only a stored upload would spend the approval")
            {
                CHECK(expired.status == 401U);
                CHECK(contains(expired.body, "m.oauth"));
                CHECK(refused.status == 403U);
                CHECK(held_after_refusal);
                CHECK(password_stage.status == 401U);
                CHECK(contains(password_stage.body, "m.oauth"));
                CHECK(held_after_password);
                CHECK(legacy.status == 401U);
                CHECK(contains(legacy.body, "m.login.password"));
                CHECK_FALSE(contains(legacy.body, "m.oauth"));
                CHECK(held_after_legacy);
                CHECK(audit_count(rt, "cross_signing.reset_used") == 0U);
            }
        }
    }
}

SCENARIO("The OAuth server metadata names the account page and its six actions", "[integration][oauth][oauth-account]")
{
    GIVEN("a server with the OAuth 2.0 API on")
    {
        auto fixture = make_fixture();
        auto& rt = fixture.started.runtime;

        WHEN("the metadata is read")
        {
            auto const response = send(rt, "GET", "/_matrix/client/v1/auth_metadata", {});

            THEN("account_management_uri is the page and every action is listed")
            {
                REQUIRE(response.status == 200U);
                CHECK(member(response, "account_management_uri") == oauth_account_url);
                for (auto const action :
                     {"org.matrix.profile", "org.matrix.devices_list", "org.matrix.device_view",
                      "org.matrix.device_delete", "org.matrix.account_deactivate", "org.matrix.cross_signing_reset"})
                {
                    CHECK(contains(response.body, std::string{"\""} + action + "\""));
                }
            }
        }
    }
}
