// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The OAuth 2.0 token and revocation endpoints against the Matrix Client-Server API v1.19: the authorisation code and
// refresh token grants, and token revocation (RFC 6749, RFC 7009).

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
#include <utility>

namespace
{

using namespace merovingian::tests;
namespace hs = merovingian::homeserver;

constexpr auto alice_password = std::string_view{"AlicePass99!x"};

struct Fixture final
{
    hs::ClientServerStartResult started;
    std::string client_id;
};

// OAuth on, alice registered, a web client registered; `access_token_lifetime_ms` as given.
[[nodiscard]] auto make_fixture(std::int64_t access_token_lifetime_ms = 3'600'000) -> Fixture
{
    auto config = oauth_registration_config();
    config.server().server_name = "example.org";
    enable_token_registration(config.security());
    config.security().access_token_lifetime_ms = access_token_lifetime_ms;
    auto started = hs::start_client_server(config);
    REQUIRE(started.started);
    REQUIRE(
        hs::register_local_user(started.runtime.homeserver, "alice", alice_password, std::string{registration_token})
            .ok);
    auto client_id = register_oauth_web_client(started.runtime, oauth_both_grant_types);
    REQUIRE_FALSE(client_id.empty());
    return {std::move(started), std::move(client_id)};
}

[[nodiscard]] auto whoami_status(hs::ClientServerRuntime& rt, std::string const& token) -> std::uint16_t
{
    return static_cast<std::uint16_t>(
        hs::handle_client_server_request(rt, {"GET", "/_matrix/client/v3/account/whoami", token, {}}, false)
            .response.status);
}

[[nodiscard]] auto oauth_error(hs::LocalHttpResponse const& response) -> std::string
{
    auto const body = parse_object(response.body);
    auto const* error = string_member(body, "error");
    return error == nullptr ? std::string{} : *error;
}

} // namespace

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: Refresh token grant, Authorisation code grant
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#refresh-token-grant
//
// "When authorisation is granted to a client, the homeserver MUST issue a refresh token to the client in addition to
// the access token. The access token MUST be short-lived". RFC 6749 section 5.1: `access_token`, `token_type`,
// `expires_in`, `refresh_token`, `scope`.
SCENARIO("An authorisation code grant issues a short-lived access token and a refresh token",
         "[conformance][client-server][oauth][oauth-token]")
{
    GIVEN("a server whose legacy access tokens never expire")
    {
        auto fixture = make_fixture(0);
        auto& rt = fixture.started.runtime;

        WHEN("alice signs in through OAuth 2.0")
        {
            auto const answer = oauth_sign_in(rt, fixture.client_id, "alice", alice_password);

            THEN("the answer holds both tokens and a finite lifetime")
            {
                REQUIRE(answer.ok);
                // Spec MUST: a refresh token is issued in addition to the access token.
                REQUIRE_FALSE(answer.refresh_token.empty());
                REQUIRE_FALSE(answer.access_token.empty());
                // Spec MUST: "The access token MUST be short-lived", whatever the legacy configuration.
                REQUIRE(answer.expires_in > 0);
                REQUIRE(answer.expires_in <= 3600);
                // RFC 6749 section 7.1: a Bearer token.
                REQUIRE(answer.token_type == "Bearer");
                REQUIRE(answer.scope == oauth_test_scope);
                REQUIRE(whoami_status(rt, answer.access_token) == 200U);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: Refresh token grant
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#refresh-token-grant
//
// "The homeserver SHOULD issue a new refresh token each time an old one is used, and invalidate the old one. However,
// it MUST ensure that the client is able to retry the refresh request in the case that the response to the request is
// lost." "The homeserver SHOULD consider that the session is compromised if an old, invalidated refresh token is used,
// and SHOULD revoke the session."
SCENARIO("The refresh token grant rotates, allows a lost answer to be retried, and revokes on reuse",
         "[conformance][client-server][oauth][oauth-refresh]")
{
    GIVEN("alice signed in through OAuth 2.0")
    {
        auto fixture = make_fixture();
        auto& rt = fixture.started.runtime;
        auto const session = oauth_sign_in(rt, fixture.client_id, "alice", alice_password);
        REQUIRE(session.ok);

        WHEN("the refresh token is used, and the answer is lost, so it is used again")
        {
            auto const lost = read_token_answer(
                post_oauth_form(rt, oauth_token_path, refresh_grant_fields(fixture.client_id, session.refresh_token)));
            auto const retried = read_token_answer(
                post_oauth_form(rt, oauth_token_path, refresh_grant_fields(fixture.client_id, session.refresh_token)));

            THEN("both requests succeed with new tokens")
            {
                // Spec MUST: the client is able to retry a refresh whose answer was lost.
                REQUIRE(lost.ok);
                REQUIRE(retried.ok);
                // Spec SHOULD: a new refresh token each time.
                REQUIRE(retried.refresh_token != session.refresh_token);
                REQUIRE(whoami_status(rt, retried.access_token) == 200U);
            }

            AND_WHEN("the new refresh token is used, and then the old one again")
            {
                auto const next = read_token_answer(post_oauth_form(
                    rt, oauth_token_path, refresh_grant_fields(fixture.client_id, retried.refresh_token)));
                REQUIRE(next.ok);
                auto const reused = post_oauth_form(rt, oauth_token_path,
                                                    refresh_grant_fields(fixture.client_id, session.refresh_token));

                THEN("the old token is refused and the session is revoked")
                {
                    // Spec SHOULD: the old refresh token is invalidated once its successor is used.
                    REQUIRE(reused.status == 400U);
                    REQUIRE(oauth_error(reused) == "invalid_grant");
                    // Spec SHOULD: reuse of an invalidated refresh token revokes the session.
                    REQUIRE(whoami_status(rt, next.access_token) == 401U);
                }
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: Token revocation
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#token-revocation
//
// "The server MUST revoke both the access token and refresh token associated with the token provided in the request."
// "If the `client_id` is not provided, or does not match the client associated with the token, the server SHOULD still
// revoke the token." "If the token is already revoked or invalid, the server returns a `200 OK` response".
SCENARIO("Token revocation revokes both tokens of the session", "[conformance][client-server][oauth][oauth-revoke]")
{
    GIVEN("alice signed in through OAuth 2.0")
    {
        auto fixture = make_fixture();
        auto& rt = fixture.started.runtime;
        auto const session = oauth_sign_in(rt, fixture.client_id, "alice", alice_password);
        REQUIRE(session.ok);

        WHEN("the access token is revoked under a client ID that is not the session's")
        {
            auto const response = post_oauth_form(rt, oauth_revoke_path,
                                                  {
                                                      {"token",           session.access_token},
                                                      {"token_type_hint", "access_token"      },
                                                      {"client_id",       "someone-else"      },
            });

            THEN("both tokens stop working")
            {
                // Spec SHOULD: revoked although the client ID does not match.
                REQUIRE(response.status == 200U);
                // Spec MUST: the access token is revoked.
                REQUIRE(whoami_status(rt, session.access_token) == 401U);
                // Spec MUST: the refresh token associated with it is revoked too.
                auto const refreshed = post_oauth_form(rt, oauth_token_path,
                                                       refresh_grant_fields(fixture.client_id, session.refresh_token));
                REQUIRE(refreshed.status == 400U);
                REQUIRE(oauth_error(refreshed) == "invalid_grant");
            }

            AND_WHEN("the same token is revoked again")
            {
                auto const again = post_oauth_form(rt, oauth_revoke_path,
                                                   {
                                                       {"token", session.access_token}
                });
                THEN("the answer is 200 OK")
                {
                    // Spec SHOULD: "If the token is already revoked or invalid, the server returns a 200 OK".
                    REQUIRE(again.status == 200U);
                }
            }
        }
        WHEN("the refresh token is revoked")
        {
            auto const response = post_oauth_form(rt, oauth_revoke_path,
                                                  {
                                                      {"token",           session.refresh_token},
                                                      {"token_type_hint", "refresh_token"      },
            });
            THEN("the access token stops working too")
            {
                REQUIRE(response.status == 200U);
                // Spec MUST: both tokens of the session are revoked.
                REQUIRE(whoami_status(rt, session.access_token) == 401U);
            }
        }
        WHEN("the token parameter is missing")
        {
            auto const response = post_oauth_form(rt, oauth_revoke_path,
                                                  {
                                                      {"token_type_hint", "access_token"}
            });
            THEN("the answer is 400 with error details")
            {
                // Spec SHOULD: "For other errors, the server returns a 400 Bad Request response with error details".
                REQUIRE(response.status == 400U);
                REQUIRE(oauth_error(response) == "invalid_request");
            }
        }
    }
}
