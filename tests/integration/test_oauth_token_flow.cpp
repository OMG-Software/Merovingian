// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// `POST /_merovingian/oauth2/token` and `POST /_merovingian/oauth2/revoke` through the client-server dispatcher, after
// a real sign-in through the authorisation pages: the authorization code grant and its one transaction, a replayed or
// mismatched code, the refresh grant and the separation of the OAuth and legacy sessions, revocation, and the
// User-Interactive Authentication endpoints answering an OAuth session (ADR-0791 to ADR-0795).

#include "../support/AppserviceTestConfig.hpp"
#include "../support/CrossSigningFixture.hpp"
#include "../support/OAuthAuthorizationSupport.hpp"
#include "../support/OAuthRegistrationSupport.hpp"
#include "../support/OAuthTokenSupport.hpp"
#include "../support/RegistrationToken.hpp"
#include "../support/TestAppservice.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/database/OAuthStore.hpp"
#include "merovingian/database/PersistentOAuthSession.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/PersistentStoreBackend.hpp"
#include "merovingian/homeserver/AuthService.hpp"
#include "merovingian/homeserver/AuthorizationCodeRedemption.hpp"
#include "merovingian/homeserver/AuthorizationCodeStore.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/LocalHttpRequest.hpp"
#include "merovingian/homeserver/LocalHttpResponse.hpp"
#include "merovingian/homeserver/OAuthClock.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace
{

using namespace merovingian::tests;
namespace db = merovingian::database;
namespace hs = merovingian::homeserver;

constexpr auto alice_password = std::string_view{"AlicePass99!x"};
constexpr auto alice_id = std::string_view{"@alice:example.org"};
constexpr auto account_url = std::string_view{"https://matrix.example.org/_merovingian/account"};

[[nodiscard]] auto token_config(bool oauth_enabled = true) -> merovingian::config::Config
{
    auto config = oauth_registration_config(oauth_enabled);
    config.server().server_name = "example.org";
    enable_token_registration(config.security());
    return config;
}

// A runtime with alice and a registered web client named "Test App".
struct Fixture final
{
    hs::ClientServerStartResult started;
    std::string client_id;
};

[[nodiscard]] auto make_fixture(
    std::string_view client_extra = R"(,"client_name":"Test App","grant_types":["authorization_code","refresh_token"])")
    -> Fixture
{
    auto started = hs::start_client_server(token_config());
    REQUIRE(started.started);
    REQUIRE(
        hs::register_local_user(started.runtime.homeserver, "alice", alice_password, std::string{registration_token})
            .ok);
    auto client_id = register_oauth_web_client(started.runtime, client_extra);
    REQUIRE_FALSE(client_id.empty());
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

[[nodiscard]] auto whoami_status(hs::ClientServerRuntime& rt, std::string const& token) -> std::uint16_t
{
    return static_cast<std::uint16_t>(send(rt, "GET", "/_matrix/client/v3/account/whoami", token).status);
}

[[nodiscard]] auto oauth_error(hs::LocalHttpResponse const& response) -> std::string
{
    auto const body = parse_object(response.body);
    auto const* error = string_member(body, "error");
    return error == nullptr ? std::string{} : *error;
}

[[nodiscard]] auto legacy_login(hs::ClientServerRuntime& rt, std::string_view device_id) -> hs::LocalHttpResponse
{
    return send(
        rt, "POST", "/_matrix/client/v3/login", {},
        R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":")" +
            std::string{alice_password} + R"(","device_id":")" + std::string{device_id} + R"(","refresh_token":true})");
}

[[nodiscard]] auto member(hs::LocalHttpResponse const& response, std::string_view name) -> std::string
{
    auto const body = parse_object(response.body);
    auto const* value = string_member(body, name);
    return value == nullptr ? std::string{} : *value;
}

[[nodiscard]] auto oauth_row(hs::ClientServerRuntime const& rt, std::string_view device_id)
    -> db::PersistentOAuthSession const*
{
    return db::find_oauth_session(rt.homeserver.database.persistent_store, alice_id, device_id);
}

[[nodiscard]] auto holds_device(hs::ClientServerRuntime const& rt, std::string_view device_id) -> bool
{
    return db::has_user_device(rt.homeserver.database.persistent_store, alice_id, device_id);
}

[[nodiscard]] auto audit_count(hs::ClientServerRuntime const& rt, std::string_view event_type) -> std::size_t
{
    return static_cast<std::size_t>(std::ranges::count_if(rt.homeserver.database.audit_events, [&](auto const& event) {
        return event.event_type == event_type;
    }));
}

auto set_locked(hs::ClientServerRuntime& rt, bool locked) -> void
{
    auto& users = rt.homeserver.database.users;
    auto const user = std::ranges::find_if(users, [](auto const& candidate) {
        return candidate.user_id == alice_id;
    });
    REQUIRE(user != users.end());
    user->locked = locked;
}

} // namespace

SCENARIO("An authorization code is exchanged for a session the client-server API accepts",
         "[integration][oauth][oauth-token]")
{
    GIVEN("alice and a registered web client named Test App")
    {
        auto fixture = make_fixture();
        auto& rt = fixture.started.runtime;
        auto const code = obtain_oauth_code(rt, fixture.client_id, "alice", alice_password);
        REQUIRE_FALSE(code.empty());

        WHEN("the client redeems the code in one request")
        {
            auto const before = db::committed_transaction_count(rt.homeserver.database.persistent_store);
            auto const response = post_oauth_form(rt, oauth_token_path, code_grant_fields(fixture.client_id, code));
            auto const after = db::committed_transaction_count(rt.homeserver.database.persistent_store);
            auto const answer = read_token_answer(response);

            THEN("it is given a Bearer access token with a finite lifetime, a refresh token and the scope")
            {
                REQUIRE(answer.ok);
                CHECK(answer.token_type == "Bearer");
                CHECK(answer.expires_in == 3600);
                CHECK(answer.scope == oauth_test_scope);
                CHECK(answer.access_token != answer.refresh_token);
                CHECK(response_header(response, "Cache-Control") == "no-store");
                CHECK(response_header(response, "Content-Type") == "application/json");
            }

            THEN("the device, both tokens, the OAuth session and its audit row were written in one transaction")
            {
                // One commit for the grant; the other two are the self device-list change POST /login also records
                // after its own write (the sync stream position, then the change row). "A grant that cannot be stored
                // leaves nothing ..." shows the grant's rows stand or fall together.
                CHECK(after - before == 3U);
                CHECK(audit_count(rt, "oauth.session.granted") == 1U);
                REQUIRE(holds_device(rt, oauth_test_device));
                auto const* row = oauth_row(rt, oauth_test_device);
                REQUIRE(row != nullptr);
                CHECK(row->client_id == fixture.client_id);
                CHECK(row->scope == oauth_test_scope);
                CHECK(audit_count(rt, "oauth.session.granted") == 1U);
            }

            THEN("the access token authenticates as alice on the device, which is named after the client")
            {
                auto const whoami = send(rt, "GET", "/_matrix/client/v3/account/whoami", answer.access_token);
                REQUIRE(whoami.status == 200U);
                CHECK(member(whoami, "user_id") == alice_id);
                CHECK(member(whoami, "device_id") == oauth_test_device);
                auto const device = send(rt, "GET", "/_matrix/client/v3/devices/" + std::string{oauth_test_device},
                                         answer.access_token);
                REQUIRE(device.status == 200U);
                CHECK(member(device, "display_name") == "Test App");
                CHECK(send(rt, "GET", "/_matrix/client/v3/sync?timeout=0", answer.access_token).status == 200U);
            }

            AND_WHEN("the same code is presented again")
            {
                auto const replay = post_oauth_form(rt, oauth_token_path, code_grant_fields(fixture.client_id, code));

                THEN("it is refused and the session it produced is ended")
                {
                    REQUIRE(replay.status == 400U);
                    CHECK(oauth_error(replay) == "invalid_grant");
                    CHECK(whoami_status(rt, answer.access_token) == 401U);
                    CHECK_FALSE(holds_device(rt, oauth_test_device));
                    CHECK(oauth_row(rt, oauth_test_device) == nullptr);
                    auto const refreshed = post_oauth_form(
                        rt, oauth_token_path, refresh_grant_fields(fixture.client_id, answer.refresh_token));
                    CHECK(oauth_error(refreshed) == "invalid_grant");
                }
            }
        }
    }
}

SCENARIO("A replayed code ends only the session it produced", "[integration][oauth][oauth-token][oauth-replay]")
{
    GIVEN("a session from a first code, replaced on the same device by a second code's session")
    {
        auto fixture = make_fixture();
        auto& rt = fixture.started.runtime;
        auto const first_code = obtain_oauth_code(rt, fixture.client_id, "alice", alice_password);
        REQUIRE_FALSE(first_code.empty());
        auto const first =
            read_token_answer(post_oauth_form(rt, oauth_token_path, code_grant_fields(fixture.client_id, first_code)));
        REQUIRE(first.ok);
        auto const second = oauth_sign_in(rt, fixture.client_id, "alice", alice_password);
        REQUIRE(second.ok);

        WHEN("the first code is presented again")
        {
            auto const replay = post_oauth_form(rt, oauth_token_path, code_grant_fields(fixture.client_id, first_code));

            THEN("it is refused, the first session's tokens are gone and the second session is untouched")
            {
                REQUIRE(replay.status == 400U);
                CHECK(oauth_error(replay) == "invalid_grant");
                CHECK(whoami_status(rt, first.access_token) == 401U);
                CHECK(whoami_status(rt, second.access_token) == 200U);
                CHECK(oauth_row(rt, oauth_test_device) != nullptr);
            }
        }
    }
}

SCENARIO("A code presented with the wrong redirect URI, verifier or client is spent",
         "[integration][oauth][oauth-token]")
{
    GIVEN("alice, the web client and a second registered client")
    {
        auto fixture = make_fixture();
        auto& rt = fixture.started.runtime;
        auto const other_client = register_oauth_web_client(
            rt, R"(,"client_name":"Other","grant_types":["authorization_code","refresh_token"])");
        REQUIRE_FALSE(other_client.empty());
        REQUIRE(other_client != fixture.client_id);

        auto const check_spent = [&](OAuthFields const& wrong, std::string const& code) {
            auto const refused = post_oauth_form(rt, oauth_token_path, wrong);
            REQUIRE(refused.status == 400U);
            CHECK(oauth_error(refused) == "invalid_grant");
            auto const retried = post_oauth_form(rt, oauth_token_path, code_grant_fields(fixture.client_id, code));
            CHECK(retried.status == 400U);
            CHECK(oauth_error(retried) == "invalid_grant");
            CHECK_FALSE(holds_device(rt, oauth_test_device));
            CHECK(oauth_row(rt, oauth_test_device) == nullptr);
        };

        WHEN("the redirect URI differs by one byte")
        {
            auto const code = obtain_oauth_code(rt, fixture.client_id, "alice", alice_password);
            REQUIRE_FALSE(code.empty());
            THEN("the code is refused and cannot be used afterwards")
            {
                check_spent(with_parameter(code_grant_fields(fixture.client_id, code), "redirect_uri",
                                           std::string{oauth_client_redirect} + "/"),
                            code);
            }
        }
        WHEN("the verifier does not match the challenge")
        {
            auto const code = obtain_oauth_code(rt, fixture.client_id, "alice", alice_password);
            REQUIRE_FALSE(code.empty());
            THEN("the code is refused and cannot be used afterwards")
            {
                check_spent(
                    with_parameter(code_grant_fields(fixture.client_id, code), "code_verifier", std::string(43U, 'a')),
                    code);
            }
        }
        WHEN("another registered client presents it")
        {
            auto const code = obtain_oauth_code(rt, fixture.client_id, "alice", alice_password);
            REQUIRE_FALSE(code.empty());
            THEN("the code is refused and cannot be used afterwards")
            {
                check_spent(code_grant_fields(other_client, code), code);
            }
        }
        WHEN("the verifier is malformed")
        {
            auto const code = obtain_oauth_code(rt, fixture.client_id, "alice", alice_password);
            REQUIRE_FALSE(code.empty());
            auto const refused =
                post_oauth_form(rt, oauth_token_path,
                                with_parameter(code_grant_fields(fixture.client_id, code), "code_verifier", "short"));
            auto const retried = post_oauth_form(rt, oauth_token_path, code_grant_fields(fixture.client_id, code));
            THEN("the request is malformed and the code is not spent")
            {
                CHECK(refused.status == 400U);
                CHECK(oauth_error(refused) == "invalid_request");
                CHECK(read_token_answer(retried).ok);
            }
        }
        WHEN("an unknown code is presented")
        {
            auto const refused =
                post_oauth_form(rt, oauth_token_path, code_grant_fields(fixture.client_id, std::string(64U, 'f')));
            THEN("it is invalid_grant")
            {
                CHECK(refused.status == 400U);
                CHECK(oauth_error(refused) == "invalid_grant");
            }
        }
    }
}

SCENARIO("A grant that cannot be stored leaves nothing, and an account that cannot sign in gets no session",
         "[integration][oauth][oauth-token]")
{
    GIVEN("alice, the web client and a fresh code")
    {
        auto fixture = make_fixture();
        auto& rt = fixture.started.runtime;
        auto const code = obtain_oauth_code(rt, fixture.client_id, "alice", alice_password);
        REQUIRE_FALSE(code.empty());

        WHEN("the transaction fails")
        {
            db::force_next_persist_failures(rt.homeserver.database.persistent_store, 1U);
            auto const response = post_oauth_form(rt, oauth_token_path, code_grant_fields(fixture.client_id, code));
            // The session a replay would end was named before the commit, so no bookkeeping follows it.
            auto const replay = rt.homeserver.oauth_codes.redeem(code, hs::oauth_wall_clock_ms());
            THEN("the answer is server_error and no device, token or session row exists")
            {
                REQUIRE(response.status == 500U);
                CHECK(oauth_error(response) == "server_error");
                CHECK_FALSE(holds_device(rt, oauth_test_device));
                CHECK(oauth_row(rt, oauth_test_device) == nullptr);
                CHECK(audit_count(rt, "oauth.session.granted") == 0U);
                CHECK(replay.outcome == hs::AuthorizationCodeRedemption::Outcome::replayed);
                CHECK(replay.session_created_at_ms.has_value());
            }
        }
        WHEN("the account is locked between the consent and the token request")
        {
            set_locked(rt, true);
            auto const response = post_oauth_form(rt, oauth_token_path, code_grant_fields(fixture.client_id, code));
            THEN("the grant is refused and nothing is written")
            {
                REQUIRE(response.status == 400U);
                CHECK(oauth_error(response) == "invalid_grant");
                CHECK_FALSE(holds_device(rt, oauth_test_device));
            }
        }
    }
}

SCENARIO(
    "A grant on a device alice already holds replaces its tokens, and a legacy login on it drops the OAuth session",
    "[integration][oauth][oauth-token]")
{
    GIVEN("alice signed in with a password on the device the OAuth request names")
    {
        auto fixture = make_fixture();
        auto& rt = fixture.started.runtime;
        auto const legacy = legacy_login(rt, oauth_test_device);
        REQUIRE(legacy.status == 200U);
        auto const legacy_access = member(legacy, "access_token");

        WHEN("an OAuth grant is made for the same device")
        {
            auto const answer = oauth_sign_in(rt, fixture.client_id, "alice", alice_password);
            THEN("the device's earlier token stops working and the OAuth one works")
            {
                REQUIRE(answer.ok);
                CHECK(whoami_status(rt, legacy_access) == 401U);
                CHECK(whoami_status(rt, answer.access_token) == 200U);
                CHECK(oauth_row(rt, oauth_test_device) != nullptr);
            }

            AND_WHEN("alice then logs in on that device with POST /login")
            {
                auto const again = legacy_login(rt, oauth_test_device);
                THEN("the device is a legacy session again: no OAuth row, and the OAuth refresh token is refused")
                {
                    REQUIRE(again.status == 200U);
                    CHECK(oauth_row(rt, oauth_test_device) == nullptr);
                    auto const refreshed = post_oauth_form(
                        rt, oauth_token_path, refresh_grant_fields(fixture.client_id, answer.refresh_token));
                    CHECK(oauth_error(refreshed) == "invalid_grant");
                    CHECK(whoami_status(rt, member(again, "access_token")) == 200U);
                }
            }
        }
    }
}

SCENARIO("The refresh grant rotates an OAuth session's tokens and only an OAuth session's",
         "[integration][oauth][oauth-token][oauth-refresh]")
{
    GIVEN("alice signed in through OAuth and, on another device, through POST /login")
    {
        auto fixture = make_fixture();
        auto& rt = fixture.started.runtime;
        auto const session = oauth_sign_in(rt, fixture.client_id, "alice", alice_password);
        REQUIRE(session.ok);
        auto const legacy = legacy_login(rt, "LEGACYDEV");
        REQUIRE(legacy.status == 200U);
        auto const legacy_refresh = member(legacy, "refresh_token");
        REQUIRE_FALSE(legacy_refresh.empty());

        WHEN("the client refreshes its session")
        {
            auto const response =
                post_oauth_form(rt, oauth_token_path, refresh_grant_fields(fixture.client_id, session.refresh_token));
            auto const rotated = read_token_answer(response);
            THEN("new tokens with the granted scope are issued, and they work")
            {
                REQUIRE(rotated.ok);
                CHECK(rotated.token_type == "Bearer");
                CHECK(rotated.expires_in == 3600);
                CHECK(rotated.scope == oauth_test_scope);
                CHECK(rotated.access_token != session.access_token);
                CHECK(rotated.refresh_token != session.refresh_token);
                CHECK(whoami_status(rt, rotated.access_token) == 200U);
                CHECK(oauth_row(rt, oauth_test_device) != nullptr);
            }
        }
        WHEN("the runtime's device list lost the device, as after a restart, and the client refreshes")
        {
            std::erase_if(rt.devices, [](auto const& device) {
                return device.user_id == alice_id && device.device_id == oauth_test_device;
            });
            auto const rotated = read_token_answer(
                post_oauth_form(rt, oauth_token_path, refresh_grant_fields(fixture.client_id, session.refresh_token)));
            auto const healed = std::ranges::find_if(rt.devices, [](auto const& device) {
                return device.user_id == alice_id && device.device_id == oauth_test_device;
            });
            THEN("the device is listed again with its stored display name, not its device ID")
            {
                REQUIRE(rotated.ok);
                REQUIRE(healed != rt.devices.end());
                CHECK(healed->display_name == "Test App");
            }
        }
        WHEN("another registered client presents the refresh token")
        {
            auto const other_client = register_oauth_web_client(
                rt, R"(,"client_name":"Other","grant_types":["authorization_code","refresh_token"])");
            REQUIRE_FALSE(other_client.empty());
            auto const refused =
                post_oauth_form(rt, oauth_token_path, refresh_grant_fields(other_client, session.refresh_token));
            auto const after =
                post_oauth_form(rt, oauth_token_path, refresh_grant_fields(fixture.client_id, session.refresh_token));
            THEN("it is invalid_grant and nothing was rotated")
            {
                CHECK(refused.status == 400U);
                CHECK(oauth_error(refused) == "invalid_grant");
                CHECK(read_token_answer(after).ok);
            }
        }
        WHEN("the legacy session's refresh token is presented to the OAuth token endpoint")
        {
            auto const refused =
                post_oauth_form(rt, oauth_token_path, refresh_grant_fields(fixture.client_id, legacy_refresh));
            auto const legacy_after =
                send(rt, "POST", "/_matrix/client/v3/refresh", {}, R"({"refresh_token":")" + legacy_refresh + R"("})");
            THEN("it is invalid_grant and the legacy session still refreshes through POST /refresh")
            {
                CHECK(refused.status == 400U);
                CHECK(oauth_error(refused) == "invalid_grant");
                CHECK(legacy_after.status == 200U);
            }
        }
        WHEN("the OAuth refresh token is presented to POST /refresh")
        {
            auto const refused = send(rt, "POST", "/_matrix/client/v3/refresh", {},
                                      R"({"refresh_token":")" + session.refresh_token + R"("})");
            auto const after =
                post_oauth_form(rt, oauth_token_path, refresh_grant_fields(fixture.client_id, session.refresh_token));
            THEN("it is an unknown token there, and the OAuth session is unchanged")
            {
                CHECK(refused.status == 401U);
                CHECK(member(refused, "errcode") == "M_UNKNOWN_TOKEN");
                CHECK(read_token_answer(after).ok);
            }
        }
        WHEN("the refresh request lacks the client ID or names an unknown client")
        {
            auto const missing = post_oauth_form(rt, oauth_token_path,
                                                 {
                                                     {"grant_type",    "refresh_token"      },
                                                     {"refresh_token", session.refresh_token},
            });
            auto const unknown =
                post_oauth_form(rt, oauth_token_path, refresh_grant_fields("not-a-client", session.refresh_token));
            THEN("they are invalid_request and invalid_client")
            {
                CHECK(oauth_error(missing) == "invalid_request");
                CHECK(oauth_error(unknown) == "invalid_client");
            }
        }
    }
}

SCENARIO("The token endpoint refuses malformed requests and client credentials",
         "[integration][oauth][oauth-token][oauth-token-refusals]")
{
    GIVEN("a registered web client")
    {
        auto fixture = make_fixture();
        auto& rt = fixture.started.runtime;
        auto const body = form_encode(code_grant_fields(fixture.client_id, std::string(64U, 'f')));

        WHEN("the body is JSON, a client_secret is sent, Basic credentials are sent, or the grant type is unknown")
        {
            auto const json =
                post_oauth_body(rt, oauth_token_path, R"({"grant_type":"authorization_code"})", "application/json");
            auto const secret = post_oauth_body(rt, oauth_token_path, body + "&client_secret=s3cret");
            auto const basic = post_oauth_body(rt, oauth_token_path, body, oauth_form_type,
                                               {
                                                   {"Authorization", "Basic YTpi"}
            });
            auto const grant = post_oauth_form(rt, oauth_token_path,
                                               {
                                                   {"grant_type", "password"       },
                                                   {"client_id",  fixture.client_id},
            });
            auto const repeated = post_oauth_body(rt, oauth_token_path, body + "&code=again");
            auto const charset =
                post_oauth_body(rt, oauth_token_path, body, "application/x-www-form-urlencoded; charset=UTF-8");

            THEN("each answer is the OAuth error RFC 6749 names, with no-store and CORS headers")
            {
                CHECK(json.status == 400U);
                CHECK(oauth_error(json) == "invalid_request");
                CHECK(secret.status == 400U);
                CHECK(oauth_error(secret) == "invalid_client");
                CHECK(basic.status == 401U);
                CHECK(oauth_error(basic) == "invalid_client");
                CHECK(response_header(basic, "WWW-Authenticate") == "Basic");
                CHECK(grant.status == 400U);
                CHECK(oauth_error(grant) == "unsupported_grant_type");
                CHECK(oauth_error(repeated) == "invalid_request");
                // The charset parameter is accepted; the code is unknown.
                CHECK(oauth_error(charset) == "invalid_grant");
                for (auto const* response : {&json, &secret, &basic, &grant})
                {
                    CHECK(response_header(*response, "Cache-Control") == "no-store");
                    CHECK_FALSE(response_header(*response, "Access-Control-Allow-Origin").empty());
                }
            }
        }
        WHEN("a client registered without the refresh_token grant asks for it")
        {
            auto const code_only = register_oauth_web_client(rt, R"(,"grant_types":["authorization_code"])");
            REQUIRE_FALSE(code_only.empty());
            auto const refused =
                post_oauth_form(rt, oauth_token_path, refresh_grant_fields(code_only, std::string(64U, 'a')));
            THEN("it is unauthorized_client")
            {
                CHECK(oauth_error(refused) == "unauthorized_client");
            }
        }
        WHEN("the endpoints are called with GET")
        {
            auto const token = send(rt, "GET", std::string{oauth_token_path}, {});
            auto const revoke = send(rt, "GET", std::string{oauth_revoke_path}, {});
            THEN("the method is not allowed")
            {
                CHECK(token.status == 405U);
                CHECK(revoke.status == 405U);
            }
        }
    }

    GIVEN("a server with the OAuth 2.0 API off")
    {
        auto started = hs::start_client_server(token_config(false));
        REQUIRE(started.started);
        WHEN("the token and revocation endpoints are called")
        {
            auto const token = post_oauth_form(started.runtime, oauth_token_path,
                                               {
                                                   {"grant_type", "refresh_token"}
            });
            auto const revoke = post_oauth_form(started.runtime, oauth_revoke_path,
                                                {
                                                    {"token", "x"}
            });
            THEN("neither route exists")
            {
                CHECK(token.status == 404U);
                CHECK(member(token, "errcode") == "M_UNRECOGNIZED");
                CHECK(revoke.status == 404U);
                CHECK(member(revoke, "errcode") == "M_UNRECOGNIZED");
            }
        }
    }
}

SCENARIO("Revocation ends the session a token belongs to, as POST /logout does", "[integration][oauth][oauth-revoke]")
{
    GIVEN("alice signed in through OAuth")
    {
        auto fixture = make_fixture();
        auto& rt = fixture.started.runtime;
        auto const session = oauth_sign_in(rt, fixture.client_id, "alice", alice_password);
        REQUIRE(session.ok);

        auto const check_ended = [&](hs::LocalHttpResponse const& response) {
            REQUIRE(response.status == 200U);
            CHECK(response.body.empty());
            CHECK(response_header(response, "Cache-Control") == "no-store");
            CHECK(whoami_status(rt, session.access_token) == 401U);
            CHECK_FALSE(holds_device(rt, oauth_test_device));
            CHECK(oauth_row(rt, oauth_test_device) == nullptr);
            CHECK(oauth_error(post_oauth_form(rt, oauth_token_path,
                                              refresh_grant_fields(fixture.client_id, session.refresh_token))) ==
                  "invalid_grant");
            CHECK(audit_count(rt, "oauth.session.revoked") == 1U);
        };

        WHEN("the access token is revoked with its hint")
        {
            auto const response = post_oauth_form(rt, oauth_revoke_path,
                                                  {
                                                      {"token",           session.access_token},
                                                      {"token_type_hint", "access_token"      },
                                                      {"client_id",       fixture.client_id   },
            });
            THEN("the session and its device are gone")
            {
                check_ended(response);
            }
        }
        WHEN("the refresh token is revoked with an unknown hint and no client ID")
        {
            auto const response = post_oauth_form(rt, oauth_revoke_path,
                                                  {
                                                      {"token",           session.refresh_token},
                                                      {"token_type_hint", "something_else"     },
            });
            THEN("the session and its device are gone")
            {
                check_ended(response);
            }
        }
        WHEN("an unknown token is revoked, or the same token twice")
        {
            auto const unknown = post_oauth_form(rt, oauth_revoke_path,
                                                 {
                                                     {"token", std::string(68U, 'a')}
            });
            auto const first = post_oauth_form(rt, oauth_revoke_path,
                                               {
                                                   {"token", session.access_token}
            });
            auto const second = post_oauth_form(rt, oauth_revoke_path,
                                                {
                                                    {"token", session.access_token}
            });
            THEN("each answer is 200 with an empty body")
            {
                CHECK(unknown.status == 200U);
                CHECK(unknown.body.empty());
                CHECK(first.status == 200U);
                CHECK(second.status == 200U);
                CHECK(second.body.empty());
            }
        }
        WHEN("the token is missing, the body is JSON, or a client_secret is sent")
        {
            auto const missing = post_oauth_form(rt, oauth_revoke_path,
                                                 {
                                                     {"token_type_hint", "access_token"}
            });
            auto const json = post_oauth_body(rt, oauth_revoke_path, R"({"token":"x"})", "application/json");
            auto const secret = post_oauth_form(rt, oauth_revoke_path,
                                                {
                                                    {"token",         session.access_token},
                                                    {"client_secret", "s"                 }
            });
            THEN("each is refused and the session remains")
            {
                CHECK(oauth_error(missing) == "invalid_request");
                CHECK(oauth_error(json) == "invalid_request");
                CHECK(oauth_error(secret) == "invalid_client");
                CHECK(whoami_status(rt, session.access_token) == 200U);
            }
        }
    }

    GIVEN("alice signed in with POST /login")
    {
        auto fixture = make_fixture();
        auto& rt = fixture.started.runtime;
        auto const legacy = legacy_login(rt, "LEGACYDEV");
        REQUIRE(legacy.status == 200U);
        WHEN("its access token is revoked")
        {
            auto const response = post_oauth_form(rt, oauth_revoke_path,
                                                  {
                                                      {"token", member(legacy, "access_token")}
            });
            THEN("the legacy session ends too")
            {
                CHECK(response.status == 200U);
                CHECK(whoami_status(rt, member(legacy, "access_token")) == 401U);
                CHECK_FALSE(holds_device(rt, "LEGACYDEV"));
            }
        }
    }
}

SCENARIO("Every User-Interactive Authentication endpoint but the m.oauth upload refuses an OAuth session",
         "[integration][oauth][oauth-uia]")
{
    GIVEN("alice signed in through OAuth and on another device with a password")
    {
        auto fixture = make_fixture();
        auto& rt = fixture.started.runtime;
        rt.homeserver.config.security().login_token.enabled = true;
        auto const session = oauth_sign_in(rt, fixture.client_id, "alice", alice_password);
        REQUIRE(session.ok);
        auto const legacy = legacy_login(rt, "LEGACYDEV");
        REQUIRE(legacy.status == 200U);
        auto const legacy_token = member(legacy, "access_token");

        struct Endpoint final
        {
            std::string_view method;
            std::string_view path;
        };
        constexpr auto endpoints = std::array<Endpoint, 6U>{
            {
             {"POST", "/_matrix/client/v1/login/get_token"},
             {"POST", "/_matrix/client/v3/account/password"},
             {"POST", "/_matrix/client/v3/account/deactivate"},
             {"POST", "/_matrix/client/v3/account/3pid/add"},
             {"DELETE", "/_matrix/client/v3/devices/LEGACYDEV"},
             {"POST", "/_matrix/client/v3/delete_devices"},
             }
        };
        auto const body = std::string{R"({"new_password":"AnotherPass77!y","client_secret":"cs","sid":"sid",)"
                                      R"("devices":["LEGACYDEV"]})"};

        WHEN("the OAuth session calls each of them")
        {
            THEN("each answers 403 M_FORBIDDEN naming the account page, and nothing changes")
            {
                for (auto const& endpoint : endpoints)
                {
                    INFO(endpoint.method << ' ' << endpoint.path);
                    auto const response =
                        send(rt, std::string{endpoint.method}, std::string{endpoint.path}, session.access_token, body);
                    CHECK(response.status == 403U);
                    CHECK(member(response, "errcode") == "M_FORBIDDEN");
                    CHECK(member(response, "error").find(account_url) != std::string::npos);
                }
                CHECK(holds_device(rt, "LEGACYDEV"));
                CHECK(whoami_status(rt, session.access_token) == 200U);
            }
        }
        WHEN("the password session calls each of them without auth")
        {
            THEN("each answers the 401 UIA challenge as before")
            {
                for (auto const& endpoint : endpoints)
                {
                    INFO(endpoint.method << ' ' << endpoint.path);
                    auto const response =
                        send(rt, std::string{endpoint.method}, std::string{endpoint.path}, legacy_token, body);
                    CHECK(response.status == 401U);
                    CHECK(response.body.find("\"flows\"") != std::string::npos);
                }
            }
        }
        WHEN("the OAuth session uploads its first cross-signing keys, then tries to replace the master key")
        {
            auto const upload = [&](std::string const& members) {
                return send(rt, "POST", "/_matrix/client/v3/keys/device_signing/upload", session.access_token,
                            "{" + members + "}");
            };
            auto const first = upload(make_cross_signing_set(std::string{alice_id}).selected_members(true, true, true));
            auto const replacement = upload(make_cross_signing_set(std::string{alice_id}).master_member());
            THEN("the first upload needs no UIA and the replacement is asked for the m.oauth stage (ADR-0797)")
            {
                CHECK(first.status == 200U);
                CHECK(replacement.status == 401U);
                CHECK(replacement.body.find(R"("stages":["m.oauth"])") != std::string::npos);
                CHECK(replacement.body.find(std::string{account_url} + "?action=org.matrix.cross_signing_reset") !=
                      std::string::npos);
            }
        }
    }
}

SCENARIO("An application service replaces cross-signing keys without User-Interactive Authentication",
         "[integration][oauth][oauth-uia][appservice]")
{
    GIVEN("an application service whose namespace holds alice, who already holds a master key")
    {
        auto bridge = TestAppservice{.id = "bridge", .users_regex = "@alice:example.org"};
        auto config = appservice_test_config({bridge});
        config.server().server_name = "example.org";
        config.server().public_baseurl = "https://matrix.example.org";
        config.server().oauth.enabled = true;
        auto started = hs::start_client_server(config);
        REQUIRE(started.started);
        auto& rt = started.runtime;
        REQUIRE(hs::register_local_user(rt.homeserver, "alice", alice_password, std::string{registration_token}).ok);
        auto const target = std::string{"/_matrix/client/v3/keys/device_signing/upload?user_id=@alice:example.org"};
        REQUIRE(send(rt, "POST", target, bridge.as_token(),
                     "{" + make_cross_signing_set(std::string{alice_id}).master_member() + "}")
                    .status == 200U);

        WHEN("it uploads a different master key with no auth")
        {
            auto const response = send(rt, "POST", target, bridge.as_token(),
                                       "{" + make_cross_signing_set(std::string{alice_id}).master_member() + "}");
            THEN("it is stored: the spec exempts application services")
            {
                CHECK(response.status == 200U);
            }
        }
    }
}

namespace
{

// Signs alice in on the authorisation page and stops at the consent page: the browser and the pending identifier the
// approval needs.
struct SignedInOnPage final
{
    BrowserContext browser;
    std::string pending;
};

[[nodiscard]] auto sign_in_on_page(hs::ClientServerRuntime& rt, std::string_view client_id) -> SignedInOnPage
{
    auto signed_in = SignedInOnPage{};
    auto const page = get_authorize(rt, oauth_authorize_parameters(client_id), signed_in.browser);
    signed_in.pending = pending_of(page);
    signed_in.browser.cookie = cookie_of(page);
    REQUIRE(page.status == 200U);
    auto const consent = post_authorize(rt,
                                        {
                                            {"pending",  signed_in.pending          },
                                            {"action",   "login"                    },
                                            {"username", "alice"                    },
                                            {"password", std::string{alice_password}},
    },
                                        signed_in.browser);
    REQUIRE(consent.status == 200U);
    return signed_in;
}

// POST /account/password from a legacy session of alice, keeping her other devices.
[[nodiscard]] auto change_password_through_client_api(hs::ClientServerRuntime& rt) -> std::uint16_t
{
    auto const login = legacy_login(rt, "PWDEVICE");
    REQUIRE(login.status == 200U);
    return static_cast<std::uint16_t>(
        send(rt, "POST", "/_matrix/client/v3/account/password", member(login, "access_token"),
             R"({"auth":{"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},)"
             R"("password":")" +
                 std::string{alice_password} + R"("},"new_password":"NewAlicePass42!y","logout_devices":false})")
            .status);
}

} // namespace

SCENARIO("A password change ends a sign-in waiting for approval and a code not yet redeemed",
         "[integration][oauth][oauth-token][credential-stamp][security]")
{
    GIVEN("alice and a registered web client")
    {
        auto fixture = make_fixture();
        auto& rt = fixture.started.runtime;

        WHEN("alice signs in on the page, then changes her password through POST /account/password, then approves")
        {
            auto const signed_in = sign_in_on_page(rt, fixture.client_id);
            REQUIRE(change_password_through_client_api(rt) == 200U);
            auto const approved = post_authorize(rt,
                                                 {
                                                     {"pending", signed_in.pending},
                                                     {"action",  "approve"        },
            },
                                                 signed_in.browser);

            THEN("the approval is the expired page, no code is sent and the entry is spent")
            {
                CHECK(approved.status == 400U);
                CHECK(approved.body.find("Sign-in expired") != std::string::npos);
                CHECK(response_header(approved, "Location").empty());
                CHECK(rt.homeserver.oauth_pending_authorisations.size() == 0U);
                CHECK(audit_count(rt, "oauth.authorization.granted") == 0U);
            }
        }

        WHEN("a code is issued, then alice's password is changed on the account page, then the code is redeemed")
        {
            auto const code = obtain_oauth_code(rt, fixture.client_id, "alice", alice_password);
            REQUIRE_FALSE(code.empty());
            REQUIRE(hs::change_password_on_account_page(rt.homeserver, alice_id, "NewAlicePass42!y").ok);
            auto const redeemed = post_oauth_form(rt, oauth_token_path, code_grant_fields(fixture.client_id, code));
            auto const again = post_oauth_form(rt, oauth_token_path, code_grant_fields(fixture.client_id, code));

            THEN("the redemption is invalid_grant, writes no session, and the code is spent")
            {
                CHECK(redeemed.status == 400U);
                CHECK(oauth_error(redeemed) == "invalid_grant");
                CHECK(oauth_error(again) == "invalid_grant");
                CHECK_FALSE(holds_device(rt, oauth_test_device));
                CHECK(oauth_row(rt, oauth_test_device) == nullptr);
                CHECK(audit_count(rt, "oauth.session.granted") == 0U);
            }
        }

        WHEN("a code is issued, then alice's password is reset by email, then the code is redeemed")
        {
            auto const code = obtain_oauth_code(rt, fixture.client_id, "alice", alice_password);
            REQUIRE_FALSE(code.empty());
            REQUIRE(hs::reset_local_user_password(rt.homeserver, alice_id, "NewAlicePass42!y", false).ok);
            auto const redeemed = post_oauth_form(rt, oauth_token_path, code_grant_fields(fixture.client_id, code));

            THEN("the redemption is invalid_grant and writes no session")
            {
                CHECK(oauth_error(redeemed) == "invalid_grant");
                CHECK(oauth_row(rt, oauth_test_device) == nullptr);
            }
        }

        WHEN("alice signs in, approves and the code is redeemed with no change in between")
        {
            auto const answer = oauth_sign_in(rt, fixture.client_id, "alice", alice_password);

            THEN("the session is granted")
            {
                CHECK(answer.ok);
                CHECK(oauth_row(rt, oauth_test_device) != nullptr);
            }
        }
    }
}

namespace
{

[[nodiscard]] auto signed_in_client(hs::ClientServerRuntime& rt, std::string_view client_id) -> OAuthTokenAnswer
{
    auto answer = oauth_sign_in(rt, client_id, "alice", alice_password);
    REQUIRE(answer.ok);
    REQUIRE(oauth_row(rt, oauth_test_device) != nullptr);
    return answer;
}

[[nodiscard]] auto password_auth() -> std::string
{
    return R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":")" +
           std::string{alice_password} + R"("})";
}

} // namespace

SCENARIO("Ending every credential of a device deletes its OAuth session row with them",
         "[integration][oauth][oauth-token][oauth-session-end][security]")
{
    GIVEN("alice with an OAuth session on OAUTHDEV01 and a legacy session on PWDEVICE")
    {
        auto fixture = make_fixture();
        auto& rt = fixture.started.runtime;
        auto const answer = signed_in_client(rt, fixture.client_id);
        auto const legacy = legacy_login(rt, "PWDEVICE");
        REQUIRE(legacy.status == 200U);
        auto const legacy_token = member(legacy, "access_token");

        WHEN("she changes her password with POST /account/password and logout_devices")
        {
            auto const changed =
                send(rt, "POST", "/_matrix/client/v3/account/password", legacy_token,
                     R"({"auth":)" + password_auth() + R"(,"new_password":"NewAlicePass42!y","logout_devices":true})");

            THEN("the OAuth device's tokens and its session row are gone, and the caller's device keeps working")
            {
                REQUIRE(changed.status == 200U);
                CHECK(whoami_status(rt, answer.access_token) == 401U);
                CHECK(oauth_row(rt, oauth_test_device) == nullptr);
                CHECK_FALSE(db::oauth_client_has_session(rt.homeserver.database.persistent_store, fixture.client_id));
                CHECK(whoami_status(rt, legacy_token) == 200U);
            }
        }

        WHEN("she changes her password on the account page")
        {
            REQUIRE(hs::change_password_on_account_page(rt.homeserver, alice_id, "NewAlicePass42!y").ok);

            THEN("the tokens and the session row are gone")
            {
                CHECK(whoami_status(rt, answer.access_token) == 401U);
                CHECK(oauth_row(rt, oauth_test_device) == nullptr);
            }
        }

        WHEN("her password is reset by email with every device signed out")
        {
            REQUIRE(hs::reset_local_user_password(rt.homeserver, alice_id, "NewAlicePass42!y", true).ok);

            THEN("the tokens and the session row are gone")
            {
                CHECK(whoami_status(rt, answer.access_token) == 401U);
                CHECK(oauth_row(rt, oauth_test_device) == nullptr);
            }
        }

        WHEN("her password is reset by email keeping her devices")
        {
            REQUIRE(hs::reset_local_user_password(rt.homeserver, alice_id, "NewAlicePass42!y", false).ok);

            THEN("the OAuth session keeps its tokens and its row")
            {
                CHECK(whoami_status(rt, answer.access_token) == 200U);
                CHECK(oauth_row(rt, oauth_test_device) != nullptr);
            }
        }

        WHEN("she deactivates her account")
        {
            auto const deactivated = send(rt, "POST", "/_matrix/client/v3/account/deactivate", legacy_token,
                                          R"({"auth":)" + password_auth() + "}");

            THEN("the tokens and the session row are gone")
            {
                REQUIRE(deactivated.status == 200U);
                CHECK(whoami_status(rt, answer.access_token) == 401U);
                CHECK(oauth_row(rt, oauth_test_device) == nullptr);
            }
        }

        WHEN("the client refreshes, and the spent refresh token is presented again")
        {
            auto const refreshed = read_token_answer(
                post_oauth_form(rt, oauth_token_path, refresh_grant_fields(fixture.client_id, answer.refresh_token)));
            REQUIRE(refreshed.ok);
            REQUIRE(whoami_status(rt, refreshed.access_token) == 200U);
            auto const reused =
                post_oauth_form(rt, oauth_token_path, refresh_grant_fields(fixture.client_id, answer.refresh_token));

            THEN("reuse ends the session: its tokens and its row are gone, and the device is no OAuth device")
            {
                CHECK(oauth_error(reused) == "invalid_grant");
                CHECK(whoami_status(rt, refreshed.access_token) == 401U);
                CHECK(oauth_row(rt, oauth_test_device) == nullptr);
            }
        }

        WHEN("the store cannot commit while the user's and the device's credentials are ended")
        {
            auto& store = rt.homeserver.database.persistent_store;
            auto const backend = store.backend;
            store.backend = db::PersistentStoreBackend::sqlite;
            store.sqlite_path.clear();
            auto const user_ended = db::revoke_user_credentials(store, alice_id, std::nullopt);
            auto const device_ended = db::revoke_device_tokens(store, alice_id, oauth_test_device);
            store.backend = backend;

            THEN("both fail, and the tokens and the session row are all still there")
            {
                CHECK_FALSE(user_ended);
                CHECK_FALSE(device_ended);
                CHECK(oauth_row(rt, oauth_test_device) != nullptr);
                CHECK(whoami_status(rt, answer.access_token) == 200U);
                CHECK(whoami_status(rt, legacy_token) == 200U);
            }
        }
    }
}

SCENARIO("A client whose only session ended with its credentials is evicted at the registration cap",
         "[integration][oauth][oauth-token][oauth-session-end][cap]")
{
    GIVEN("alice signed in to Test App, at a cap of one client")
    {
        auto fixture = make_fixture();
        auto& rt = fixture.started.runtime;
        std::ignore = signed_in_client(rt, fixture.client_id);
        rt.limits.max_oauth_clients = 1U;
        auto const other_client = std::string{
            R"({"client_uri":"https://other.example.com/","redirect_uris":[)"
            R"("https://other.example.com/cb"],"token_endpoint_auth_method":"none","client_name":"Other"})"};

        WHEN("her password is changed on the account page, then another client registers")
        {
            REQUIRE(hs::change_password_on_account_page(rt.homeserver, alice_id, "NewAlicePass42!y").ok);
            auto const registered = post_client_registration(rt, other_client);

            THEN("the ended session no longer protects Test App, which is evicted")
            {
                CHECK(registered.status == 201U);
                CHECK(db::find_oauth_client(rt.homeserver.database.persistent_store, fixture.client_id) == nullptr);
            }
        }

        WHEN("another client registers while her session is live")
        {
            auto const refused = post_client_registration(rt, other_client);

            THEN("Test App is kept and the new client refused")
            {
                CHECK(refused.status == 503U);
                CHECK(db::find_oauth_client(rt.homeserver.database.persistent_store, fixture.client_id) != nullptr);
            }
        }
    }
}
