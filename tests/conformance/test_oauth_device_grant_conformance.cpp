// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The device authorisation grant against the Matrix Client-Server API v1.19 (RFC 8628): the device authorisation
// response, the token polling errors, and the refresh token a granted device receives.

#include "../support/OAuthAuthorizationSupport.hpp"
#include "../support/OAuthRegistrationSupport.hpp"
#include "../support/OAuthTokenSupport.hpp"
#include "../support/RegistrationToken.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/homeserver/AuthService.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/LocalHttpRequest.hpp"
#include "merovingian/homeserver/LocalHttpResponse.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>

namespace
{

using namespace merovingian::tests;
namespace hs = merovingian::homeserver;

constexpr auto alice_password = std::string_view{"AlicePass99!x"};
constexpr auto device_path = std::string_view{"/_merovingian/oauth2/device"};
constexpr auto link_path = std::string_view{"/_merovingian/oauth2/link"};
constexpr auto device_grant = std::string_view{"urn:ietf:params:oauth:grant-type:device_code"};

struct Fixture final
{
    hs::ClientServerStartResult started;
    std::string client_id;
};

// OAuth and the device grant on, alice registered, a client registered for the device and refresh grants.
[[nodiscard]] auto make_fixture() -> Fixture
{
    auto config = oauth_registration_config();
    config.server().server_name = "example.org";
    config.server().oauth.device_grant_enabled = true;
    enable_token_registration(config.security());
    auto started = hs::start_client_server(config);
    REQUIRE(started.started);
    started.runtime.rate_limit_engine.reset();
    REQUIRE(
        hs::register_local_user(started.runtime.homeserver, "alice", alice_password, std::string{registration_token})
            .ok);
    auto client_id = register_oauth_web_client(
        started.runtime, R"(,"grant_types":["urn:ietf:params:oauth:grant-type:device_code","refresh_token"])");
    REQUIRE_FALSE(client_id.empty());
    return {std::move(started), std::move(client_id)};
}

[[nodiscard]] auto member(hs::LocalHttpResponse const& response, std::string_view name) -> std::string
{
    auto const body = parse_object(response.body);
    auto const* value = string_member(body, name);
    return value == nullptr ? std::string{} : *value;
}

[[nodiscard]] auto request_codes(hs::ClientServerRuntime& rt, std::string_view client_id) -> hs::LocalHttpResponse
{
    return post_oauth_form(rt, device_path,
                           {
                               {"client_id", std::string{client_id}              },
                               {"scope",     oauth_scope_for_device("CONFDEVICE")},
    });
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

// Alice types `user_code` on the link page, signs in and answers `action`.
[[nodiscard]] auto user_answers(hs::ClientServerRuntime& rt, std::string_view user_code, std::string_view action)
    -> hs::LocalHttpResponse
{
    auto browser = BrowserContext{};
    auto const page = authorize_request(rt, "GET", std::string{link_path}, {}, browser);
    browser.cookie = cookie_of(page);
    auto const login = authorize_request(rt, "POST",
                                         std::string{
                                             link_path
    },
                                         form_encode({{"user_code", std::string{user_code}}}), browser);
    auto const pending = pending_of(login);
    std::ignore = post_authorize(rt,
                                 {
                                     {"pending",  pending                    },
                                     {"action",   "login"                    },
                                     {"username", "alice"                    },
                                     {"password", std::string{alice_password}},
    },
                                 browser);
    return post_authorize(rt,
                          {
                              {"pending", pending            },
                              {"action",  std::string{action}},
    },
                          browser);
}

} // namespace

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: Device authorisation flow
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#device-authorisation-flow
//
// "The server responds with a JSON object as defined in RFC 8628 section 3.2, containing: device_code, user_code,
// verification_uri, verification_uri_complete, expires_in, interval". "It is RECOMMENDED that the server provides a
// verification_uri_complete".
SCENARIO("The device authorisation response holds every RFC 8628 member",
         "[conformance][client-server][oauth][oauth-device]")
{
    GIVEN("a client registered for the device grant")
    {
        auto fixture = make_fixture();
        auto& rt = fixture.started.runtime;

        WHEN("it sends the device authorisation request")
        {
            auto const response = request_codes(rt, fixture.client_id);

            THEN("the answer is JSON with the six members, and the complete URI names the user code")
            {
                REQUIRE(response.status == 200U);
                auto const body = parse_object(response.body);
                REQUIRE_FALSE(member(response, "device_code").empty());
                REQUIRE_FALSE(member(response, "user_code").empty());
                REQUIRE(member(response, "verification_uri") == "https://matrix.example.org/_merovingian/oauth2/link");
                // Spec RECOMMENDED: a URI that does not require the user to type the code.
                REQUIRE(member(response, "verification_uri_complete") ==
                        member(response, "verification_uri") + "?user_code=" + member(response, "user_code"));
                auto const* expires_in = int_member(body, "expires_in");
                auto const* interval = int_member(body, "interval");
                REQUIRE(expires_in != nullptr);
                REQUIRE(*expires_in > 0);
                REQUIRE(interval != nullptr);
                REQUIRE(*interval >= 5);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: Device authorisation flow (Token polling)
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#device-authorisation-flow
//
// "While authorisation is pending, the server returns an authorization_pending error (or slow_down if the client is
// polling too frequently). If authorisation is denied, the server returns an access_denied error. If the device code
// expires, the server returns an expired_token error." RFC 8628 section 3.5: each is an RFC 6749 section 5.2 error
// response, HTTP 400.
SCENARIO("Token polling answers the RFC 8628 section 3.5 errors", "[conformance][client-server][oauth][oauth-device]")
{
    GIVEN("a pending device authorisation")
    {
        auto fixture = make_fixture();
        auto& rt = fixture.started.runtime;
        auto const codes = request_codes(rt, fixture.client_id);
        auto const device_code = member(codes, "device_code");
        REQUIRE_FALSE(device_code.empty());

        WHEN("the client polls twice at once")
        {
            auto const first = poll(rt, fixture.client_id, device_code);
            auto const second = poll(rt, fixture.client_id, device_code);

            THEN("it hears authorization_pending, then slow_down, both 400")
            {
                REQUIRE(first.status == 400U);
                REQUIRE(member(first, "error") == "authorization_pending");
                REQUIRE(second.status == 400U);
                REQUIRE(member(second, "error") == "slow_down");
            }
        }

        WHEN("the user denies and the client polls")
        {
            auto const denied = user_answers(rt, member(codes, "user_code"), "deny");
            rt.homeserver.test_device_grant_clock_advance_ms += 5'000U;
            auto const polled = poll(rt, fixture.client_id, device_code);

            THEN("it hears access_denied")
            {
                REQUIRE(denied.status == 200U);
                REQUIRE(polled.status == 400U);
                REQUIRE(member(polled, "error") == "access_denied");
            }
        }

        WHEN("the device code expires and the client polls")
        {
            rt.homeserver.test_device_grant_clock_advance_ms += 600'000U;
            auto const polled = poll(rt, fixture.client_id, device_code);

            THEN("it hears expired_token")
            {
                REQUIRE(polled.status == 400U);
                REQUIRE(member(polled, "error") == "expired_token");
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: Device authorisation grant
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#device-authorisation-grant
//
// "when authorisation is granted to a client, the homeserver MUST issue a refresh token to the client in addition to
// the access token." The client "can call the /whoami endpoint to get the user ID that owns the access token".
SCENARIO("A granted device receives an access token and a refresh token",
         "[conformance][client-server][oauth][oauth-device]")
{
    GIVEN("a device authorisation that alice allows")
    {
        auto fixture = make_fixture();
        auto& rt = fixture.started.runtime;
        auto const codes = request_codes(rt, fixture.client_id);
        auto const allowed = user_answers(rt, member(codes, "user_code"), "approve");
        REQUIRE(allowed.status == 200U);

        WHEN("the client polls")
        {
            auto const answer = read_token_answer(poll(rt, fixture.client_id, member(codes, "device_code")));

            THEN("the answer holds both tokens, Bearer, a finite lifetime and the scope, and whoami names alice")
            {
                REQUIRE(answer.ok);
                // Spec MUST: a refresh token in addition to the access token.
                REQUIRE_FALSE(answer.refresh_token.empty());
                REQUIRE(answer.token_type == "Bearer");
                REQUIRE(answer.expires_in > 0);
                REQUIRE(answer.scope == oauth_scope_for_device("CONFDEVICE"));
                auto const whoami =
                    hs::handle_client_server_request(
                        rt, {"GET", "/_matrix/client/v3/account/whoami", answer.access_token, {}}, false)
                        .response;
                REQUIRE(whoami.status == 200U);
                REQUIRE(member(whoami, "user_id") == "@alice:example.org");
            }

            AND_WHEN("the refresh token is used")
            {
                auto const refreshed = read_token_answer(post_oauth_form(
                    rt, oauth_token_path, refresh_grant_fields(fixture.client_id, answer.refresh_token)));

                THEN("the refresh token grant serves it")
                {
                    REQUIRE(refreshed.ok);
                }
            }
        }
    }
}
