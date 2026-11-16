// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The device authorization grant through the client-server dispatcher (RFC 8628; plan P11; ADR-0804 to ADR-0806): a
// device asks for codes at POST /_merovingian/oauth2/device, a user types the user code at /_merovingian/oauth2/link,
// signs in, and allows or denies; the device polls the token endpoint. The clock is moved with
// `HomeserverRuntime::test_device_grant_clock_advance_ms`, so nothing sleeps. No browser runs here: what a browser does
// with the cookie or the page is not tested.

#include "../support/JsonTestSupport.hpp"
#include "../support/OAuthAuthorizationSupport.hpp"
#include "../support/OAuthRegistrationSupport.hpp"
#include "../support/OAuthTokenSupport.hpp"
#include "../support/RegistrationToken.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/homeserver/AuthService.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/DeviceAuthorisationStore.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/LocalHttpRequest.hpp"
#include "merovingian/homeserver/LocalHttpResponse.hpp"
#include "merovingian/homeserver/OAuthClock.hpp"
#include "merovingian/homeserver/RetentionSweep.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace
{

using namespace merovingian::tests;
namespace hs = merovingian::homeserver;

constexpr auto alice_password = std::string_view{"AlicePass99!x"};
constexpr auto alice_id = std::string_view{"@alice:example.org"};
constexpr auto device_path = std::string_view{"/_merovingian/oauth2/device"};
constexpr auto link_path = std::string_view{"/_merovingian/oauth2/link"};
constexpr auto link_url = std::string_view{"https://matrix.example.org/_merovingian/oauth2/link"};
constexpr auto device_grant = std::string_view{"urn:ietf:params:oauth:grant-type:device_code"};
constexpr auto tv_device = std::string_view{"TVDEVICE01"};
constexpr auto device_client_members = std::string_view{
    R"(,"client_name":"Living Room TV","grant_types":["urn:ietf:params:oauth:grant-type:device_code","refresh_token"])"};

[[nodiscard]] auto device_config(bool device_grant_enabled = true) -> merovingian::config::Config
{
    auto config = oauth_registration_config(true);
    config.server().server_name = "example.org";
    config.server().oauth.device_grant_enabled = device_grant_enabled;
    enable_token_registration(config.security());
    return config;
}

// A runtime with alice, a device client and a web client registered without the device grant.
struct Fixture final
{
    hs::ClientServerStartResult started;
    std::string client_id;
    std::string web_client_id;
};

[[nodiscard]] auto make_fixture(bool device_grant_enabled = true) -> Fixture
{
    auto started = hs::start_client_server(device_config(device_grant_enabled));
    REQUIRE(started.started);
    // Every request comes from one or two addresses; the built-in limits are not what this file tests.
    started.runtime.rate_limit_engine.reset();
    REQUIRE(
        hs::register_local_user(started.runtime.homeserver, "alice", alice_password, std::string{registration_token})
            .ok);
    auto client_id = register_oauth_web_client(started.runtime, device_client_members);
    REQUIRE_FALSE(client_id.empty());
    auto web_client_id = register_oauth_web_client(started.runtime);
    REQUIRE_FALSE(web_client_id.empty());
    return {std::move(started), std::move(client_id), std::move(web_client_id)};
}

[[nodiscard]] auto contains(std::string_view text, std::string_view part) -> bool
{
    return text.find(part) != std::string_view::npos;
}

[[nodiscard]] auto member(hs::LocalHttpResponse const& response, std::string_view name) -> std::string
{
    auto const body = parse_object(response.body);
    auto const* value = string_member(body, name);
    return value == nullptr ? std::string{} : *value;
}

[[nodiscard]] auto audit_count(hs::HomeserverRuntime const& runtime, std::string_view event_type) -> std::size_t
{
    auto count = std::size_t{0U};
    for (auto const& event : runtime.database.audit_events)
    {
        if (event.event_type == event_type)
        {
            ++count;
        }
    }
    return count;
}

auto advance(hs::ClientServerRuntime& rt, std::uint64_t milliseconds) -> void
{
    rt.homeserver.test_device_grant_clock_advance_ms += milliseconds;
}

// What POST /device answered.
struct DeviceStart final
{
    hs::LocalHttpResponse response;
    std::string device_code;
    std::string user_code;
};

[[nodiscard]] auto start_device(hs::ClientServerRuntime& rt, std::string_view client_id,
                                std::string_view device_id = tv_device) -> DeviceStart
{
    auto response = post_oauth_form(rt, device_path,
                                    {
                                        {"client_id", std::string{client_id}           },
                                        {"scope",     oauth_scope_for_device(device_id)},
    });
    auto device_code = member(response, "device_code");
    auto user_code = member(response, "user_code");
    return {std::move(response), std::move(device_code), std::move(user_code)};
}

[[nodiscard]] auto poll(hs::ClientServerRuntime& rt, std::string_view client_id, std::string_view device_code)
    -> hs::LocalHttpResponse
{
    return post_oauth_form(rt, oauth_token_path,
                           {
                               {"grant_type",  std::string{device_grant}},
                               {"device_code", std::string{device_code} },
                               {"client_id",   std::string{client_id}   },
    });
}

[[nodiscard]] auto oauth_error(hs::LocalHttpResponse const& response) -> std::string
{
    return member(response, "error");
}

// A browser that opened the link page: it holds the cookie the page set.
[[nodiscard]] auto open_link(hs::ClientServerRuntime& rt, std::string_view query = {},
                             std::string_view remote_addr = "198.51.100.20")
    -> std::pair<hs::LocalHttpResponse, BrowserContext>
{
    auto browser = BrowserContext{};
    browser.remote_addr = std::string{remote_addr};
    auto target = std::string{link_path};
    if (!query.empty())
    {
        target.append("?").append(query);
    }
    auto response = authorize_request(rt, "GET", target, {}, browser);
    browser.cookie = cookie_of(response);
    return {std::move(response), std::move(browser)};
}

[[nodiscard]] auto post_link(hs::ClientServerRuntime& rt, BrowserContext const& browser, std::string_view user_code)
    -> hs::LocalHttpResponse
{
    return authorize_request(rt, "POST",
                             std::string{
                                 link_path
    },
                             form_encode({{"user_code", std::string{user_code}}}), browser);
}

[[nodiscard]] auto sign_in(hs::ClientServerRuntime& rt, BrowserContext const& browser, std::string_view pending)
    -> hs::LocalHttpResponse
{
    return post_authorize(rt,
                          {
                              {"pending",  std::string{pending}       },
                              {"action",   "login"                    },
                              {"username", "alice"                    },
                              {"password", std::string{alice_password}},
    },
                          browser);
}

[[nodiscard]] auto answer(hs::ClientServerRuntime& rt, BrowserContext const& browser, std::string_view pending,
                          std::string_view action) -> hs::LocalHttpResponse
{
    return post_authorize(rt,
                          {
                              {"pending", std::string{pending}},
                              {"action",  std::string{action} },
    },
                          browser);
}

[[nodiscard]] auto whoami(hs::ClientServerRuntime& rt, std::string token) -> hs::LocalHttpResponse
{
    return hs::handle_client_server_request(rt, {"GET", "/_matrix/client/v3/account/whoami", std::move(token), {}},
                                            /*can_wait=*/false)
        .response;
}

// Types the code in a fresh browser and signs alice in: the consent page and what it needs to be answered.
struct ConsentStep final
{
    hs::LocalHttpResponse consent;
    BrowserContext browser;
    std::string pending;
};

[[nodiscard]] auto reach_consent(hs::ClientServerRuntime& rt, std::string_view user_code) -> ConsentStep
{
    auto [page, browser] = open_link(rt);
    REQUIRE(page.status == 200U);
    auto const login = post_link(rt, browser, user_code);
    REQUIRE(login.status == 200U);
    auto pending = pending_of(login);
    REQUIRE_FALSE(pending.empty());
    auto consent = sign_in(rt, browser, pending);
    return {std::move(consent), std::move(browser), std::move(pending)};
}

} // namespace

SCENARIO("A device signs in with a user code that alice types and allows", "[integration][oauth][oauth-device]")
{
    GIVEN("a server with the device grant on and a device client")
    {
        auto fixture = make_fixture();
        auto& rt = fixture.started.runtime;

        WHEN("the device asks for codes")
        {
            auto const device = start_device(rt, fixture.client_id);

            THEN("it is told both codes, the link page, ten minutes and five seconds, with CORS and no-store")
            {
                REQUIRE(device.response.status == 200U);
                auto const body = parse_object(device.response.body);
                REQUIRE(device.device_code.size() == 64U);
                REQUIRE(device.user_code.size() == 9U);
                CHECK(device.user_code[4] == '-');
                CHECK(member(device.response, "verification_uri") == link_url);
                CHECK(member(device.response, "verification_uri_complete") ==
                      std::string{link_url} + "?user_code=" + device.user_code);
                auto const* expires_in = int_member(body, "expires_in");
                auto const* interval = int_member(body, "interval");
                REQUIRE(expires_in != nullptr);
                REQUIRE(interval != nullptr);
                CHECK(*expires_in == 600);
                CHECK(*interval == 5);
                CHECK(response_header(device.response, "Cache-Control") == "no-store");
                CHECK_FALSE(response_header(device.response, "Access-Control-Allow-Origin").empty());
            }

            AND_WHEN("it polls before alice answers")
            {
                auto const pending = poll(rt, fixture.client_id, device.device_code);

                THEN("it hears authorization_pending")
                {
                    CHECK(pending.status == 400U);
                    CHECK(oauth_error(pending) == "authorization_pending");
                }
            }

            AND_WHEN("alice opens the complete link, sends the prefilled code and signs in")
            {
                auto const query = "user_code=" + device.user_code;
                auto [page, browser] = open_link(rt, query);
                auto const login = post_link(rt, browser, device.user_code);
                auto const pending = pending_of(login);
                auto const consent = sign_in(rt, browser, pending);

                THEN("the link page is prefilled and sets the cookie, the login page offers no registration, and the "
                     "consent page warns before it names the code, the client, alice and the device")
                {
                    REQUIRE(page.status == 200U);
                    CHECK(contains(page.body, "value=\"" + device.user_code + "\""));
                    CHECK(browser.cookie.size() == 64U);
                    CHECK(response_header(page, "Access-Control-Allow-Origin").empty());
                    REQUIRE(login.status == 200U);
                    CHECK(contains(login.body, R"(autocomplete="current-password")"));
                    CHECK_FALSE(contains(login.body, R"(value="show_register")"));
                    REQUIRE(consent.status == 200U);
                    auto const warning = consent.body.find("not this browser");
                    auto const code = consent.body.find(device.user_code);
                    REQUIRE(warning != std::string::npos);
                    REQUIRE(code != std::string::npos);
                    CHECK(warning < code);
                    CHECK(contains(consent.body, "Living Room TV"));
                    CHECK(contains(consent.body, "app.example.com"));
                    CHECK(contains(consent.body, alice_id));
                    CHECK(contains(consent.body, tv_device));
                    CHECK(response_header(consent, "Location").empty());
                }

                AND_WHEN("she allows it and the device polls once its interval has passed, then again")
                {
                    auto const approved = answer(rt, browser, pending, "approve");
                    advance(rt, 5'000U);
                    auto const granted = poll(rt, fixture.client_id, device.device_code);
                    auto const tokens = read_token_answer(granted);
                    advance(rt, 5'000U);
                    auto const again = poll(rt, fixture.client_id, device.device_code);

                    THEN("the page sends her back to the device, which gets tokens for its device once")
                    {
                        REQUIRE(approved.status == 200U);
                        CHECK(contains(approved.body, "Return to your other device"));
                        CHECK(response_header(approved, "Location").empty());
                        REQUIRE(tokens.ok);
                        CHECK(tokens.token_type == "Bearer");
                        CHECK(tokens.scope == oauth_scope_for_device(tv_device));
                        CHECK_FALSE(tokens.refresh_token.empty());
                        auto const me = whoami(rt, tokens.access_token);
                        REQUIRE(me.status == 200U);
                        CHECK(member(me, "user_id") == alice_id);
                        CHECK(member(me, "device_id") == tv_device);
                        CHECK(again.status == 400U);
                        CHECK(oauth_error(again) == "expired_token");
                        CHECK(audit_count(rt.homeserver, "oauth.device.approved") == 1U);
                    }
                }

                AND_WHEN("she denies it and the device polls twice")
                {
                    auto const denied = answer(rt, browser, pending, "deny");
                    advance(rt, 5'000U);
                    auto const first = poll(rt, fixture.client_id, device.device_code);
                    advance(rt, 5'000U);
                    auto const second = poll(rt, fixture.client_id, device.device_code);
                    auto const retyped = post_link(rt, browser, device.user_code);

                    THEN("the device hears access_denied each time, and the code is no longer accepted")
                    {
                        REQUIRE(denied.status == 200U);
                        CHECK(contains(denied.body, "was not let into your account"));
                        CHECK(first.status == 400U);
                        CHECK(oauth_error(first) == "access_denied");
                        CHECK(oauth_error(second) == "access_denied");
                        CHECK(retyped.status == 400U);
                        CHECK(audit_count(rt.homeserver, "oauth.device.denied") == 1U);
                    }
                }

                AND_WHEN("she asks for the registration form instead")
                {
                    auto const registration = answer(rt, browser, pending, "show_register");

                    THEN("it is refused: a device sign-in never creates an account")
                    {
                        CHECK(registration.status == 403U);
                    }
                }
            }
        }
    }
}

SCENARIO("A device that polls too fast is slowed down, and one that waits too long has expired",
         "[integration][oauth][oauth-device]")
{
    GIVEN("a pending device authorisation")
    {
        auto fixture = make_fixture();
        auto& rt = fixture.started.runtime;
        auto const device = start_device(rt, fixture.client_id);
        REQUIRE(device.response.status == 200U);

        WHEN("the device polls twice at once, then five seconds later, then ten seconds after that")
        {
            auto const first = poll(rt, fixture.client_id, device.device_code);
            auto const second = poll(rt, fixture.client_id, device.device_code);
            advance(rt, 5'000U);
            auto const third = poll(rt, fixture.client_id, device.device_code);
            advance(rt, 15'000U);
            auto const fourth = poll(rt, fixture.client_id, device.device_code);

            THEN("the second and third are slow_down, and the fourth waited out the grown interval")
            {
                CHECK(oauth_error(first) == "authorization_pending");
                CHECK(second.status == 400U);
                CHECK(oauth_error(second) == "slow_down");
                CHECK(oauth_error(third) == "slow_down");
                CHECK(oauth_error(fourth) == "authorization_pending");
            }
        }

        WHEN("ten minutes pass and the device polls and alice types the code")
        {
            advance(rt, hs::DeviceAuthorisationStore::lifetime_ms);
            auto const late = poll(rt, fixture.client_id, device.device_code);
            auto [page, browser] = open_link(rt);
            auto const typed = post_link(rt, browser, device.user_code);

            THEN("the device hears expired_token and the code is the wrong-code page")
            {
                CHECK(late.status == 400U);
                CHECK(oauth_error(late) == "expired_token");
                CHECK(typed.status == 400U);
                CHECK(contains(typed.body, "not right, or it has expired"));
            }
        }
    }
}

SCENARIO("A device code serves only its own client, and the grant serves only clients registered for it",
         "[integration][oauth][oauth-device][security]")
{
    GIVEN("a pending device authorisation and a client without the device grant")
    {
        auto fixture = make_fixture();
        auto& rt = fixture.started.runtime;
        auto const device = start_device(rt, fixture.client_id);
        REQUIRE(device.response.status == 200U);

        WHEN("the other client polls with the device code, asks for codes, and an unknown client asks")
        {
            auto const stolen = poll(rt, fixture.web_client_id, device.device_code);
            auto const unregistered = start_device(rt, fixture.web_client_id);
            auto const unknown = start_device(rt, "not-a-client");
            auto const made_up = poll(rt, fixture.client_id, "not-a-device-code");

            THEN("each is refused, and the device code still works for its own client")
            {
                CHECK(stolen.status == 400U);
                CHECK(oauth_error(stolen) == "unauthorized_client");
                CHECK(unregistered.response.status == 400U);
                CHECK(oauth_error(unregistered.response) == "unauthorized_client");
                CHECK(unknown.response.status == 400U);
                CHECK(oauth_error(unknown.response) == "invalid_client");
                CHECK(oauth_error(made_up) == "expired_token");
                CHECK(oauth_error(poll(rt, fixture.client_id, device.device_code)) == "authorization_pending");
            }
        }

        WHEN("a second device client polls with the first one's device code")
        {
            auto const second_client = register_oauth_web_client(
                rt, R"(,"client_name":"Other TV","grant_types":["urn:ietf:params:oauth:grant-type:device_code"])");
            REQUIRE_FALSE(second_client.empty());
            auto const stolen = poll(rt, second_client, device.device_code);

            THEN("it hears invalid_grant")
            {
                CHECK(stolen.status == 400U);
                CHECK(oauth_error(stolen) == "invalid_grant");
            }
        }

        WHEN("the client's registration retention is asked about")
        {
            auto const now_ms = hs::oauth_device_clock_ms(rt.homeserver);
            auto const pending = hs::oauth_client_has_pending_authorisation(rt.homeserver, fixture.client_id, now_ms);
            auto const after = hs::oauth_client_has_pending_authorisation(
                rt.homeserver, fixture.client_id, now_ms + hs::DeviceAuthorisationStore::lifetime_ms);

            THEN("the live device authorisation keeps the client, and stops keeping it once it expired")
            {
                CHECK(pending);
                CHECK_FALSE(after);
            }
        }

        WHEN("the same address asks for codes until the store refuses")
        {
            auto statuses = std::vector<std::uint16_t>{};
            for (auto index = 0U; index < hs::DeviceAuthorisationStore::max_entries_per_address; ++index)
            {
                statuses.push_back(start_device(rt, fixture.client_id).response.status);
            }

            THEN("the ninth from one address is 503 temporarily_unavailable")
            {
                // The GIVEN step's request was the first of the eight.
                for (auto index = std::size_t{0U}; index + 1U < statuses.size(); ++index)
                {
                    CHECK(statuses[index] == 200U);
                }
                CHECK(statuses.back() == 503U);
                CHECK(oauth_error(start_device(rt, fixture.client_id).response) == "temporarily_unavailable");
            }
        }
    }
}

SCENARIO("The link page throttles wrong codes per address and refuses foreign or cookieless posts",
         "[integration][oauth][oauth-device][security]")
{
    GIVEN("a pending device authorisation and a browser on the link page")
    {
        auto fixture = make_fixture();
        auto& rt = fixture.started.runtime;
        auto const device = start_device(rt, fixture.client_id);
        REQUIRE(device.response.status == 200U);
        auto [page, browser] = open_link(rt);
        REQUIRE(page.status == 200U);

        WHEN("five wrong codes are typed, then the right one")
        {
            auto wrong = std::vector<std::uint16_t>{};
            for (auto const* typed : {"BCDF-GHJK", "nonsense", "ZZZZ-ZZZZ", "", "XXXX-XXXX"})
            {
                wrong.push_back(post_link(rt, browser, typed).status);
            }
            auto const right = post_link(rt, browser, device.user_code);
            auto [other_page, other_browser] = open_link(rt, {}, "203.0.113.50");
            auto const elsewhere = post_link(rt, other_browser, device.user_code);

            THEN("each wrong code is the same 400 page, the right one is then 429 with Retry-After, and another "
                 "address is not blocked")
            {
                // A typed code that is the real one by chance would make this flaky; the odds are 5 in 20^8.
                for (auto const status : wrong)
                {
                    CHECK(status == 400U);
                }
                CHECK(right.status == 429U);
                auto const retry = response_header(right, "Retry-After");
                REQUIRE_FALSE(retry.empty());
                CHECK(std::stoul(retry) <= 600U);
                CHECK(pending_of(right).empty());
                CHECK(elsewhere.status == 200U);
            }

            AND_WHEN("ten minutes pass")
            {
                advance(rt, 600'000U);
                auto const fresh = start_device(rt, fixture.client_id);
                auto const later = post_link(rt, browser, fresh.user_code);

                THEN("the address may type codes again")
                {
                    CHECK(later.status == 200U);
                }
            }
        }

        WHEN("a post comes from another origin, and one comes without the cookie six times")
        {
            auto foreign = browser;
            foreign.origin = "https://evil.example.net";
            auto const refused = post_link(rt, foreign, device.user_code);
            auto cookieless = browser;
            cookieless.cookie.clear();
            auto missing = std::vector<hs::LocalHttpResponse>{};
            for (auto attempt = 0U; attempt < 6U; ++attempt)
            {
                missing.push_back(post_link(rt, cookieless, device.user_code));
            }
            auto const right = post_link(rt, browser, device.user_code);

            THEN("the foreign post is 403, the cookieless ones get the form and a cookie, and none counted")
            {
                CHECK(refused.status == 403U);
                for (auto const& response : missing)
                {
                    CHECK(response.status == 400U);
                    CHECK_FALSE(cookie_of(response).empty());
                    CHECK(pending_of(response).empty());
                }
                CHECK(right.status == 200U);
                CHECK_FALSE(pending_of(right).empty());
            }
        }
    }
}

SCENARIO("One browser at a time signs in for a user code", "[integration][oauth][oauth-device][security]")
{
    GIVEN("a pending device authorisation that a first browser has typed the code for")
    {
        auto fixture = make_fixture();
        auto& rt = fixture.started.runtime;
        auto const device = start_device(rt, fixture.client_id);
        REQUIRE(device.response.status == 200U);
        auto [first_page, first] = open_link(rt);
        auto const first_login = post_link(rt, first, device.user_code);
        REQUIRE(first_login.status == 200U);
        auto const first_pending = pending_of(first_login);

        WHEN("a second browser types the code at once")
        {
            auto [second_page, second] = open_link(rt, {}, "203.0.113.50");
            auto const busy = post_link(rt, second, device.user_code);

            THEN("it is 409 with Retry-After and gets no sign-in")
            {
                CHECK(busy.status == 409U);
                CHECK_FALSE(response_header(busy, "Retry-After").empty());
                CHECK(pending_of(busy).empty());
            }
        }

        WHEN("the lease lapses, a second browser takes over, and the first then signs in")
        {
            advance(rt, hs::DeviceAuthorisationStore::attachment_lease_ms);
            auto [second_page, second] = open_link(rt, {}, "203.0.113.50");
            auto const second_login = post_link(rt, second, device.user_code);
            auto const first_consent = sign_in(rt, first, first_pending);
            auto const second_consent = sign_in(rt, second, pending_of(second_login));
            auto const second_approved = answer(rt, second, pending_of(second_login), "approve");
            auto const granted = poll(rt, fixture.client_id, device.device_code);

            THEN("the first browser's sign-in has ended, and the second one's approval signs the device in")
            {
                REQUIRE(second_login.status == 200U);
                CHECK(first_consent.status == 400U);
                CHECK(contains(first_consent.body, "Device sign-in ended"));
                CHECK(second_consent.status == 200U);
                CHECK(second_approved.status == 200U);
                CHECK(read_token_answer(granted).ok);
            }
        }
    }

    GIVEN("a device authorisation the first browser has reached consent for")
    {
        auto fixture = make_fixture();
        auto& rt = fixture.started.runtime;
        auto const device = start_device(rt, fixture.client_id);
        auto step = reach_consent(rt, device.user_code);
        REQUIRE(step.consent.status == 200U);

        WHEN("it approves after another browser took the code over")
        {
            advance(rt, hs::DeviceAuthorisationStore::attachment_lease_ms);
            auto [other_page, other] = open_link(rt, {}, "203.0.113.50");
            auto const taken = post_link(rt, other, device.user_code);
            auto const approved = answer(rt, step.browser, step.pending, "approve");
            advance(rt, 5'000U);
            auto const polled = poll(rt, fixture.client_id, device.device_code);

            THEN("the approval is the ended page and the device is still pending")
            {
                REQUIRE(taken.status == 200U);
                CHECK(approved.status == 400U);
                CHECK(oauth_error(polled) == "authorization_pending");
                CHECK(audit_count(rt.homeserver, "oauth.device.approved") == 0U);
            }
        }
    }
}

SCENARIO("With the device grant off, its routes do not exist and the token endpoint refuses the grant",
         "[integration][oauth][oauth-device]")
{
    GIVEN("a server with the OAuth 2.0 API on and the device grant off")
    {
        auto fixture = make_fixture(false);
        auto& rt = fixture.started.runtime;

        WHEN("a device asks for codes, a browser opens the link page, and the grant is polled")
        {
            auto const device = start_device(rt, fixture.client_id);
            auto [page, browser] = open_link(rt);
            auto const posted = post_link(rt, browser, "BCDF-GHJK");
            auto const polled = poll(rt, fixture.client_id, "anything");
            auto const metadata = hs::handle_client_server_request(
                                      rt, {"GET", "/_matrix/client/v1/auth_metadata", {}, {}}, /*can_wait=*/false)
                                      .response;

            THEN("the routes are 404 M_UNRECOGNIZED, the grant is unsupported_grant_type, and no device endpoint is "
                 "advertised")
            {
                CHECK(device.response.status == 404U);
                CHECK(member(device.response, "errcode") == "M_UNRECOGNIZED");
                CHECK(page.status == 404U);
                CHECK(posted.status == 404U);
                CHECK(polled.status == 400U);
                CHECK(oauth_error(polled) == "unsupported_grant_type");
                REQUIRE(metadata.status == 200U);
                CHECK_FALSE(contains(metadata.body, "device_authorization_endpoint"));
            }
        }
    }

    GIVEN("a server with the device grant on")
    {
        auto fixture = make_fixture();
        auto& rt = fixture.started.runtime;

        WHEN("the metadata is read")
        {
            auto const metadata = hs::handle_client_server_request(
                                      rt, {"GET", "/_matrix/client/v1/auth_metadata", {}, {}}, /*can_wait=*/false)
                                      .response;

            THEN("it names the device endpoint and the grant")
            {
                REQUIRE(metadata.status == 200U);
                CHECK(contains(
                    metadata.body,
                    R"("device_authorization_endpoint":"https://matrix.example.org/_merovingian/oauth2/device")"));
                CHECK(contains(metadata.body, device_grant));
            }
        }
    }
}

SCENARIO("A password change ends a device sign-in that is not yet approved or not yet polled",
         "[integration][oauth][oauth-device][credential-stamp][security]")
{
    GIVEN("a device waiting for alice, who signed in on the link page with her password")
    {
        auto fixture = make_fixture();
        auto& rt = fixture.started.runtime;
        auto const device = start_device(rt, fixture.client_id);
        auto step = reach_consent(rt, device.user_code);
        REQUIRE(step.consent.status == 200U);

        WHEN("her password is reset by email before she allows the device")
        {
            REQUIRE(hs::reset_local_user_password(rt.homeserver, alice_id, "NewAlicePass42!y", true).ok);
            auto const approved = answer(rt, step.browser, step.pending, "approve");
            advance(rt, 5'000U);
            auto const polled = poll(rt, fixture.client_id, device.device_code);

            THEN("the approval is refused as expired and the device is still waiting, with no device created")
            {
                CHECK(approved.status == 400U);
                CHECK(contains(approved.body, "Sign-in expired"));
                CHECK(oauth_error(polled) == "authorization_pending");
                CHECK(audit_count(rt.homeserver, "oauth.device.approved") == 0U);
                CHECK_FALSE(merovingian::database::has_user_device(rt.homeserver.database.persistent_store, alice_id,
                                                                   tv_device));
            }
        }

        WHEN("she allows the device and her password is changed on the account page before it polls")
        {
            REQUIRE(answer(rt, step.browser, step.pending, "approve").status == 200U);
            REQUIRE(hs::change_password_on_account_page(rt.homeserver, alice_id, "NewAlicePass42!y").ok);
            advance(rt, 5'000U);
            auto const polled = poll(rt, fixture.client_id, device.device_code);
            advance(rt, 5'000U);
            auto const again = poll(rt, fixture.client_id, device.device_code);

            THEN("the poll is invalid_grant, the device code is spent, and no session was granted")
            {
                CHECK(polled.status == 400U);
                CHECK(oauth_error(polled) == "invalid_grant");
                CHECK(oauth_error(again) == "expired_token");
                CHECK(audit_count(rt.homeserver, "oauth.session.granted") == 0U);
                CHECK_FALSE(merovingian::database::has_user_device(rt.homeserver.database.persistent_store, alice_id,
                                                                   tv_device));
            }
        }

        WHEN("she allows the device and nothing changes before it polls")
        {
            REQUIRE(answer(rt, step.browser, step.pending, "approve").status == 200U);
            advance(rt, 5'000U);
            auto const tokens = read_token_answer(poll(rt, fixture.client_id, device.device_code));

            THEN("the device gets its tokens")
            {
                CHECK(tokens.ok);
            }
        }
    }
}
