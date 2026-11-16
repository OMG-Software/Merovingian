// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |           LEGACY AUTHENTICATION API BESIDE OAUTH 2.0 CONFORMANCE        |
// |                                                                         |
// |  Spec: Matrix Client-Server API v1.19 — "Authentication API discovery", |
// |        "GET /login", "POST /login" (m.login.application_service),       |
// |        "POST /register", "OAuth 2.0 aware clients"                      |
// |  URL:  ../../docs/matrix-v1.19-spec/client-server-api.md                |
// +-------------------------------------------------------------------------+
//
// What a server without the legacy authentication API answers (plan P9, ADR-0801).

#include "../support/AppserviceTestConfig.hpp"
#include "../support/JsonTestSupport.hpp"
#include "../support/TestAppservice.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/LocalHttpRequest.hpp"
#include "merovingian/homeserver/LocalHttpResponse.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <string_view>
#include <utility>

namespace
{

using namespace merovingian::tests;
namespace hs = merovingian::homeserver;

[[nodiscard]] auto bridge() -> TestAppservice
{
    auto appservice = TestAppservice{};
    appservice.id = "bridge";
    appservice.users_regex = "@_bridge_.*";
    return appservice;
}

[[nodiscard]] auto start_without_legacy_api() -> hs::ClientServerStartResult
{
    auto config = appservice_test_config({bridge()});
    config.server().public_baseurl = "https://matrix.example.org";
    config.server().oauth.enabled = true;
    config.server().oauth.legacy_api_enabled = false;
    auto started = hs::start_client_server(config);
    REQUIRE(started.started);
    started.runtime.rate_limit_engine.reset();
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

[[nodiscard]] auto errcode(hs::LocalHttpResponse const& response) -> std::string
{
    auto const body = parse_object(response.body);
    auto const* value = string_member(body, "errcode");
    return value == nullptr ? std::string{} : *value;
}

} // namespace

// Spec: CS API v1.19 "GET /login", 404: "With M_UNRECOGNIZED: the homeserver does not support the legacy authentication
// API." "Authentication API discovery": "the server SHOULD respond with 404 and an M_UNRECOGNIZED error code if the
// corresponding API is not supported."
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv3login
SCENARIO("A server without the legacy API answers GET /login with 404 M_UNRECOGNIZED",
         "[oauth][legacy-api][conformance]")
{
    GIVEN("a server with the legacy authentication API off")
    {
        auto started = start_without_legacy_api();

        WHEN("GET /login is read")
        {
            auto const response = send(started.runtime, "GET", "/_matrix/client/v3/login", {});

            THEN("it is 404 M_UNRECOGNIZED")
            {
                REQUIRE(response.status == 404U);
                REQUIRE(errcode(response) == "M_UNRECOGNIZED");
            }
        }
    }
}

// Spec: CS API v1.19 "Appservice Login": "If this login type is used and the server doesn't support logging in via the
// Legacy authentication API, it MUST return a 400 HTTP status code with an M_APPSERVICE_LOGIN_UNSUPPORTED error code."
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#post_matrixclientv3login
SCENARIO("A server without the legacy API refuses m.login.application_service with M_APPSERVICE_LOGIN_UNSUPPORTED",
         "[oauth][legacy-api][conformance][appservice]")
{
    GIVEN("a server with the legacy authentication API off and a registered appservice")
    {
        auto started = start_without_legacy_api();

        WHEN("the appservice logs in one of its users")
        {
            auto const response =
                send(started.runtime, "POST", "/_matrix/client/v3/login", bridge().as_token(),
                     R"({"type":"m.login.application_service","identifier":{"type":"m.id.user","user":"_bridge_a"}})");

            THEN("it is 400 M_APPSERVICE_LOGIN_UNSUPPORTED")
            {
                REQUIRE(response.status == 400U);
                REQUIRE(errcode(response) == "M_APPSERVICE_LOGIN_UNSUPPORTED");
            }
        }
    }
}

// Spec: CS API v1.19 "POST /register": "Even if the server doesn't support the Legacy authentication API, it MUST
// support this endpoint for application services to be able to create users. In that case application services MUST
// set the "inhibit_login": true parameter as they cannot use it to log in as users. If the inhibit_login parameter is
// not set to true, the server MUST return a 400 HTTP status code with an M_APPSERVICE_LOGIN_UNSUPPORTED error code."
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#post_matrixclientv3register
SCENARIO("A server without the legacy API still registers appservice users that set inhibit_login",
         "[oauth][legacy-api][conformance][appservice]")
{
    GIVEN("a server with the legacy authentication API off and a registered appservice")
    {
        auto started = start_without_legacy_api();

        WHEN("the appservice registers a user without inhibit_login")
        {
            auto const response = send(started.runtime, "POST", "/_matrix/client/v3/register", bridge().as_token(),
                                       R"({"type":"m.login.application_service","username":"_bridge_a"})");

            THEN("it is 400 M_APPSERVICE_LOGIN_UNSUPPORTED")
            {
                REQUIRE(response.status == 400U);
                REQUIRE(errcode(response) == "M_APPSERVICE_LOGIN_UNSUPPORTED");
            }
        }

        WHEN("the appservice registers a user with inhibit_login true")
        {
            auto const response =
                send(started.runtime, "POST", "/_matrix/client/v3/register", bridge().as_token(),
                     R"({"type":"m.login.application_service","username":"_bridge_a","inhibit_login":true})");

            THEN("the user is registered")
            {
                REQUIRE(response.status == 200U);
                auto const body = parse_object(response.body);
                auto const* user_id = string_member(body, "user_id");
                REQUIRE(user_id != nullptr);
                REQUIRE(*user_id == "@_bridge_a:example.org");
                REQUIRE(string_member(body, "access_token") == nullptr);
            }
        }
    }
}

// Spec: CS API v1.19 "POST /register", 403: "The homeserver does not permit registering the account. This response can
// be used to identify ... that registration is generally not supported by the homeserver." "Account registration":
// "With the OAuth 2.0 API, a client can't register a new account directly."
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#post_matrixclientv3register
SCENARIO("A server without the legacy API refuses a user's registration with 403", "[oauth][legacy-api][conformance]")
{
    GIVEN("a server with the legacy authentication API off")
    {
        auto started = start_without_legacy_api();

        WHEN("a client registers a user with no auth")
        {
            auto const response = send(started.runtime, "POST", "/_matrix/client/v3/register", {},
                                       R"({"username":"carol","password":"CarolPass99!x"})");

            THEN("it is 403 M_FORBIDDEN, not a User-Interactive Authentication challenge")
            {
                REQUIRE(response.status == 403U);
                REQUIRE(errcode(response) == "M_FORBIDDEN");
            }
        }
    }
}
