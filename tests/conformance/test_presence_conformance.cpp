// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |         MATRIX PRESENCE CONFORMANCE TESTS                                |
// |                                                                          |
// |  Spec: Matrix Client-Server API v1.19                                    |
// |  URL:  ../../docs/matrix-v1.19-spec/client-server-api.md                   |
// |                                                                          |
// |  Covers PUT /_matrix/client/v3/presence/{userId}/status.                 |
// +-------------------------------------------------------------------------+

#include "../support/master_key.hpp"
#include "../support/json_test_support.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/client_server.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

namespace
{

using namespace merovingian::tests;

[[nodiscard]] auto conformance_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    // A runtime refuses to mint a signing secret it cannot encrypt at rest
    // (0.12.5 audit, finding 1), so every fixture needs a master key.
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    return {
        merovingian::config::ServerConfig{},           merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},         security,
        merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto logged_in_token(merovingian::homeserver::ClientServerRuntime& runtime,
                                   std::string_view localpart = "alice") -> std::string
{
    auto const reg = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST",
                  "/_matrix/client/v3/register",
                  {},
                  merovingian::tests::registration_json(localpart, "CorrectHorse7!")});
    REQUIRE(reg.response.status == 200U);

    auto const login_body =
        std::string{"{\"type\":\"m.login.password\",\"identifier\":{\"type\":\"m.id.user\",\"user\":\"@"} +
        std::string{localpart} + ":example.org\"},\"password\":\"CorrectHorse7!\",\"device_id\":\"DEVICE1\"}";
    auto const login = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST", "/_matrix/client/v3/login", {}, login_body});
    REQUIRE(login.response.status == 200U);

    auto const body = parse_object(login.response.body);
    auto const* token = string_member(body, "access_token");
    REQUIRE(token != nullptr);
    REQUIRE(!token->empty());
    return *token;
}

} // namespace

// Spec: Matrix Client-Server API v1.19
// Endpoint: PUT /_matrix/client/v3/presence/{userId}/status
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#put_matrixclientv3presenceuserIdstatus
//
// A valid presence update is accepted and returns an empty 200 response.
SCENARIO("PUT /presence/{userId}/status accepts a valid presence update", "[conformance][client-server][presence]")
{
    GIVEN("a running client-server with a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("the user sets their presence to online with a status message")
        {
            auto const update = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"PUT", "/_matrix/client/v3/presence/@alice:example.org/status", token,
                                  R"({"presence":"online","status_msg":"available for chat"})"});

            THEN("the server returns 200 with an empty object")
            {
                REQUIRE(update.response.status == 200U);
                auto const body = parse_object(update.response.body);
                REQUIRE(body.empty());
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint: PUT /_matrix/client/v3/presence/{userId}/status
//
// Users MUST NOT be able to set presence state for other users.
SCENARIO("PUT /presence/{userId}/status rejects cross-user updates with M_FORBIDDEN",
         "[conformance][client-server][presence]")
{
    GIVEN("a running client-server with two logged-in users")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const alice_token = logged_in_token(started.runtime, "alice");
        auto const bob_token = logged_in_token(started.runtime, "bob");

        WHEN("bob tries to set alice's presence")
        {
            auto const update = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"PUT", "/_matrix/client/v3/presence/@alice:example.org/status", bob_token,
                                  R"({"presence":"unavailable"})"});

            THEN("the server responds with 403 M_FORBIDDEN")
            {
                REQUIRE(update.response.status == 403U);
                auto const body = parse_object(update.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_FORBIDDEN");
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint: PUT /_matrix/client/v3/presence/{userId}/status
//
// The request body MUST be a JSON object; a malformed body is rejected with
// M_BAD_JSON.
SCENARIO("PUT /presence/{userId}/status rejects a malformed body with M_BAD_JSON",
         "[conformance][client-server][presence]")
{
    GIVEN("a running client-server with a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        WHEN("the user sends a malformed presence body")
        {
            auto const update = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"PUT", "/_matrix/client/v3/presence/@alice:example.org/status", token, "not-json"});

            THEN("the server responds with 400 M_BAD_JSON")
            {
                REQUIRE(update.response.status == 400U);
                auto const body = parse_object(update.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_BAD_JSON");
            }
        }
    }
}
