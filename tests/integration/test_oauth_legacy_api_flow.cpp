// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// `server.oauth.legacy_api_enabled=false` through the client-server dispatcher (plan P9, ADR-0813, ADR-0801): no legacy
// endpoint lists the logins or issues a user a new session, application services still register with
// `inhibit_login`, and a session issued before carries on. With the key true nothing changes; every other test in the
// suite runs with it true.

#include "../support/AppserviceTestConfig.hpp"
#include "../support/JsonTestSupport.hpp"
#include "../support/RegistrationToken.hpp"
#include "../support/TestAppservice.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/homeserver/AuthService.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/LocalHttpRequest.hpp"
#include "merovingian/homeserver/LocalHttpResponse.hpp"
#include "merovingian/homeserver/LocalUser.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>

namespace
{

using namespace merovingian::tests;
namespace hs = merovingian::homeserver;

constexpr auto alice_id = std::string_view{"@alice:example.org"};
constexpr auto alice_password = std::string_view{"AlicePass99!x"};

[[nodiscard]] auto bridge() -> TestAppservice
{
    auto appservice = TestAppservice{};
    appservice.id = "bridge";
    appservice.users_regex = "@_bridge_.*";
    return appservice;
}

// The OAuth 2.0 API on, the legacy API on or off, login tokens on (so get_token would be served), one appservice.
[[nodiscard]] auto legacy_config(bool legacy_api_enabled) -> merovingian::config::Config
{
    auto config = appservice_test_config({bridge()});
    config.server().public_baseurl = "https://matrix.example.org";
    config.server().oauth.enabled = true;
    config.server().oauth.legacy_api_enabled = legacy_api_enabled;
    config.security().login_token.enabled = true;
    return config;
}

[[nodiscard]] auto start(bool legacy_api_enabled) -> hs::ClientServerStartResult
{
    auto started = hs::start_client_server(legacy_config(legacy_api_enabled));
    REQUIRE(started.started);
    // Every request comes from one address; the built-in limits are not what this file tests.
    started.runtime.rate_limit_engine.reset();
    REQUIRE(
        hs::register_local_user(started.runtime.homeserver, "alice", alice_password, std::string{registration_token})
            .ok);
    return started;
}

[[nodiscard]] auto send(hs::ClientServerRuntime& rt, std::string method, std::string target, std::string token,
                        std::string body = {}) -> hs::LocalHttpResponse
{
    return hs::handle_client_server_request(rt,
                                            {std::move(method), std::move(target), std::move(token), std::move(body)},
                                            /*can_wait=*/false)
        .response;
}

[[nodiscard]] auto member(hs::LocalHttpResponse const& response, std::string_view name) -> std::string
{
    auto const body = parse_object(response.body);
    auto const* value = string_member(body, name);
    return value == nullptr ? std::string{} : *value;
}

[[nodiscard]] auto user_exists(hs::ClientServerRuntime const& rt, std::string_view user_id) -> bool
{
    return std::ranges::any_of(rt.homeserver.database.users, [user_id](hs::LocalUser const& user) {
        return user.user_id == user_id;
    });
}

[[nodiscard]] auto password_login_body(std::string_view device_id) -> std::string
{
    return R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"alice"},"password":")" +
           std::string{alice_password} + R"(","device_id":")" + std::string{device_id} + R"("})";
}

// A legacy session alice holds from before the switch: the access token and its refresh token.
struct LegacySession final
{
    std::string access_token;
    std::string refresh_token;
};

[[nodiscard]] auto legacy_session(hs::ClientServerRuntime& rt, std::string_view device_id) -> LegacySession
{
    auto const login = hs::login_local_user(rt.homeserver, alice_id, alice_password, device_id, true, "127.0.0.1");
    REQUIRE(login.ok);
    auto const refresh = hs::issue_refresh_token_for_session(rt.homeserver, alice_id, device_id);
    REQUIRE(refresh.ok);
    return {login.value, refresh.value};
}

} // namespace

SCENARIO("With the legacy API off no legacy endpoint lists the logins or issues a user a session",
         "[oauth][legacy-api][client-server]")
{
    GIVEN("a server with the OAuth 2.0 API on, the legacy API off and login tokens on")
    {
        auto started = start(false);
        auto& rt = started.runtime;

        WHEN("GET /login is read")
        {
            auto const response = send(rt, "GET", "/_matrix/client/v3/login", {});

            THEN("it is 404 M_UNRECOGNIZED")
            {
                REQUIRE(response.status == 404U);
                CHECK(member(response, "errcode") == "M_UNRECOGNIZED");
            }
        }

        WHEN("alice logs in with her right password, or with a login token")
        {
            auto const password = send(rt, "POST", "/_matrix/client/v3/login", {}, password_login_body("NEWDEV"));
            auto const token = send(rt, "POST", "/_matrix/client/v3/login", {},
                                    R"({"type":"m.login.token","token":"0123456789abcdef"})");

            THEN("each is 404 M_UNRECOGNIZED and no device is created")
            {
                REQUIRE(password.status == 404U);
                CHECK(member(password, "errcode") == "M_UNRECOGNIZED");
                REQUIRE(token.status == 404U);
                CHECK(member(token, "errcode") == "M_UNRECOGNIZED");
                CHECK_FALSE(merovingian::database::has_user_device(rt.homeserver.database.persistent_store, alice_id,
                                                                   "NEWDEV"));
            }
        }

        WHEN("a user registers with a complete registration-token stage")
        {
            auto const response = send(
                rt, "POST", "/_matrix/client/v3/register", {},
                R"({"username":"carol","password":"CarolPass99!x","auth":{"type":"m.login.registration_token","token":")" +
                    std::string{registration_token} + R"("}})");

            THEN("it is 403 M_FORBIDDEN and no account is created")
            {
                REQUIRE(response.status == 403U);
                CHECK(member(response, "errcode") == "M_FORBIDDEN");
                CHECK_FALSE(user_exists(rt, "@carol:example.org"));
            }
        }

        WHEN("the appservice logs in one of its users")
        {
            auto const response = send(
                rt, "POST", "/_matrix/client/v3/login", bridge().as_token(),
                R"({"type":"m.login.application_service","identifier":{"type":"m.id.user","user":"_bridge_ann"}})");

            THEN("it is 400 M_APPSERVICE_LOGIN_UNSUPPORTED")
            {
                REQUIRE(response.status == 400U);
                CHECK(member(response, "errcode") == "M_APPSERVICE_LOGIN_UNSUPPORTED");
            }
        }

        WHEN("the appservice registers a user without inhibit_login, and with inhibit_login false")
        {
            auto const absent = send(rt, "POST", "/_matrix/client/v3/register", bridge().as_token(),
                                     R"({"type":"m.login.application_service","username":"_bridge_ann"})");
            auto const negative =
                send(rt, "POST", "/_matrix/client/v3/register", bridge().as_token(),
                     R"({"type":"m.login.application_service","username":"_bridge_ann","inhibit_login":false})");

            THEN("each is 400 M_APPSERVICE_LOGIN_UNSUPPORTED and the user is not created")
            {
                REQUIRE(absent.status == 400U);
                CHECK(member(absent, "errcode") == "M_APPSERVICE_LOGIN_UNSUPPORTED");
                REQUIRE(negative.status == 400U);
                CHECK(member(negative, "errcode") == "M_APPSERVICE_LOGIN_UNSUPPORTED");
                CHECK_FALSE(user_exists(rt, "@_bridge_ann:example.org"));
            }
        }

        WHEN("the appservice registers a user with inhibit_login true")
        {
            auto const response =
                send(rt, "POST", "/_matrix/client/v3/register", bridge().as_token(),
                     R"({"type":"m.login.application_service","username":"_bridge_ann","inhibit_login":true})");

            THEN("the user is created and no access token is returned")
            {
                REQUIRE(response.status == 200U);
                CHECK(member(response, "user_id") == "@_bridge_ann:example.org");
                CHECK(member(response, "access_token").empty());
                CHECK(user_exists(rt, "@_bridge_ann:example.org"));
            }
        }

        WHEN("a browser follows either SSO redirect endpoint")
        {
            auto const plain = send(
                rt, "GET", "/_matrix/client/v3/login/sso/redirect?redirectUrl=https%3A%2F%2Fapp.example.com%2F", {});
            auto const with_idp =
                send(rt, "GET",
                     "/_matrix/client/v3/login/sso/redirect/oidc?redirectUrl=https%3A%2F%2Fapp.example.com%2F", {});

            THEN("each is 404 M_UNRECOGNIZED")
            {
                REQUIRE(plain.status == 404U);
                CHECK(member(plain, "errcode") == "M_UNRECOGNIZED");
                REQUIRE(with_idp.status == 404U);
                CHECK(member(with_idp, "errcode") == "M_UNRECOGNIZED");
            }
        }

        WHEN("a signed-in user asks for a login token and reads the capabilities")
        {
            auto const session = legacy_session(rt, "LEGACYDEV");
            auto const get_token = send(rt, "POST", "/_matrix/client/v1/login/get_token", session.access_token, "{}");
            auto const capabilities = send(rt, "GET", "/_matrix/client/v3/capabilities", session.access_token);

            THEN("get_token is 404 M_UNRECOGNIZED and the capability says it is not enabled")
            {
                REQUIRE(get_token.status == 404U);
                CHECK(member(get_token, "errcode") == "M_UNRECOGNIZED");
                REQUIRE(capabilities.status == 200U);
                CHECK(capabilities.body.find(R"("m.get_login_token":{"enabled":false})") != std::string::npos);
            }
        }

        WHEN("the endpoints the switch leaves alone are called")
        {
            auto const available = send(rt, "GET", "/_matrix/client/v3/register/available?username=dave", {});

            THEN("they answer as before")
            {
                REQUIRE(available.status == 200U);
            }
        }
    }
}

SCENARIO("With the legacy API off a session issued before carries on", "[oauth][legacy-api][client-server]")
{
    GIVEN("a server with the legacy API off and two legacy sessions of alice")
    {
        auto started = start(false);
        auto& rt = started.runtime;
        auto const first = legacy_session(rt, "LEGACYONE");
        auto const second = legacy_session(rt, "LEGACYTWO");

        WHEN("the first session calls an authenticated endpoint")
        {
            auto const whoami = send(rt, "GET", "/_matrix/client/v3/account/whoami", first.access_token);

            THEN("it is served")
            {
                REQUIRE(whoami.status == 200U);
                CHECK(member(whoami, "user_id") == alice_id);
            }
        }

        WHEN("the first session refreshes its token")
        {
            auto const refreshed = send(rt, "POST", "/_matrix/client/v3/refresh", {},
                                        R"({"refresh_token":")" + first.refresh_token + R"("})");
            auto const new_token = member(refreshed, "access_token");

            THEN("a new access token is issued and works")
            {
                REQUIRE(refreshed.status == 200U);
                REQUIRE_FALSE(new_token.empty());
                CHECK(send(rt, "GET", "/_matrix/client/v3/account/whoami", new_token).status == 200U);
            }
        }

        WHEN("the first session deletes the second device with the password stage")
        {
            auto const deleted = send(
                rt, "DELETE", "/_matrix/client/v3/devices/LEGACYTWO", first.access_token,
                R"({"auth":{"type":"m.login.password","identifier":{"type":"m.id.user","user":"alice"},"password":")" +
                    std::string{alice_password} + R"("}})");

            THEN("User-Interactive Authentication completes and the second session ends")
            {
                REQUIRE(deleted.status == 200U);
                CHECK(send(rt, "GET", "/_matrix/client/v3/account/whoami", second.access_token).status == 401U);
            }
        }

        WHEN("the first session logs out, and the second logs out everywhere")
        {
            auto const logout = send(rt, "POST", "/_matrix/client/v3/logout", first.access_token, "{}");
            auto const logout_all = send(rt, "POST", "/_matrix/client/v3/logout/all", second.access_token, "{}");

            THEN("both are served and both tokens stop working")
            {
                REQUIRE(logout.status == 200U);
                REQUIRE(logout_all.status == 200U);
                CHECK(send(rt, "GET", "/_matrix/client/v3/account/whoami", first.access_token).status == 401U);
                CHECK(send(rt, "GET", "/_matrix/client/v3/account/whoami", second.access_token).status == 401U);
            }
        }
    }
}

SCENARIO("With both APIs on an appservice registration without inhibit_login still logs in",
         "[oauth][legacy-api][client-server][appservice]")
{
    GIVEN("a server with the OAuth 2.0 API and the legacy API on")
    {
        auto started = start(true);
        auto& rt = started.runtime;

        WHEN("the appservice registers a user without inhibit_login")
        {
            auto const response = send(rt, "POST", "/_matrix/client/v3/register", bridge().as_token(),
                                       R"({"type":"m.login.application_service","username":"_bridge_bob"})");

            THEN("the user is created and an access token is returned, as before")
            {
                REQUIRE(response.status == 200U);
                CHECK(member(response, "user_id") == "@_bridge_bob:example.org");
                CHECK_FALSE(member(response, "access_token").empty());
            }
        }
    }
}
