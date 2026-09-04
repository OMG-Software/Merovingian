// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |         MATRIX SAFETY REPORT CONFORMANCE TESTS                         |
// |                                                                         |
// |  Spec: Matrix Client-Server API v1.19                                   |
// |  URL:  ../../docs/matrix-v1.19-spec/client-server-api.md                |
// |                                                                         |
// |  Covers POST /_matrix/client/v3/rooms/{roomId}/report/{eventId} and      |
// |  the admin GET /_matrix/client/v3/admin/safety/reports audit surface.   |
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

[[nodiscard]] auto admin_token(merovingian::homeserver::ClientServerRuntime& runtime,
                               std::string_view localpart = "admin") -> std::string
{
    auto const boot =
        merovingian::homeserver::bootstrap_admin_user(runtime.homeserver, std::string{localpart}, "CorrectHorse7!");
    REQUIRE(boot.ok);

    auto const login_body =
        std::string{"{\"type\":\"m.login.password\",\"identifier\":{\"type\":\"m.id.user\",\"user\":\"@"} +
        std::string{localpart} + ":example.org\"},\"password\":\"CorrectHorse7!\",\"device_id\":\"ADMIN_DEV\"}";
    auto const login = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST", "/_matrix/client/v3/login", {}, login_body});
    REQUIRE(login.response.status == 200U);

    auto const body = parse_object(login.response.body);
    auto const* token = string_member(body, "access_token");
    REQUIRE(token != nullptr);
    REQUIRE(!token->empty());
    return *token;
}

[[nodiscard]] auto create_room(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token)
    -> std::string
{
    auto const response = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST", "/_matrix/client/v3/createRoom", token, R"({"name":"safety report room"})"});
    REQUIRE(response.response.status == 200U);
    auto const body = parse_object(response.response.body);
    auto const* room_id = string_member(body, "room_id");
    REQUIRE(room_id != nullptr);
    REQUIRE(!room_id->empty());
    return *room_id;
}

[[nodiscard]] auto send_message(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token,
                                std::string const& room_id) -> std::string
{
    auto const txn_id = std::string{"safety-msg-"} + room_id;
    auto const response = merovingian::homeserver::handle_client_server_request(
        runtime, {"PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/" + txn_id, token,
                  R"({"msgtype":"m.text","body":"report me"})"});
    REQUIRE(response.response.status == 200U);
    auto const body = parse_object(response.response.body);
    auto const* event_id = string_member(body, "event_id");
    REQUIRE(event_id != nullptr);
    REQUIRE(!event_id->empty());
    return *event_id;
}

} // namespace

// Spec: Matrix Client-Server API v1.19
// Endpoint: POST /_matrix/client/v3/rooms/{roomId}/report/{eventId}
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#post_matrixclientv3roomsroomidreporteventid
//
// The homeserver MUST accept a report containing at least a reason string and
// return 200 with an empty JSON object.
SCENARIO("POST /rooms/{roomId}/report/{eventId} accepts a valid safety report",
         "[conformance][client-server][trust-safety][report]")
{
    GIVEN("a running client-server with a logged-in user, a room, and a message")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);
        auto const event_id = send_message(started.runtime, token, room_id);

        WHEN("the user reports the event with a reason")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/rooms/" + room_id + "/report/" + event_id, token, R"({"reason":"spam"})"});

            THEN("the server returns 200 with an empty object")
            {
                // Spec MUST: 200 success, body is {}.
                REQUIRE(response.response.status == 200U);
                REQUIRE(response.response.body == "{}");
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint: POST /_matrix/client/v3/rooms/{roomId}/report/{eventId}
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#post_matrixclientv3roomsroomidreporteventid
//
// A malformed request body MUST be rejected with 400 M_BAD_JSON.
SCENARIO("POST /rooms/{roomId}/report/{eventId} rejects a non-JSON body",
         "[conformance][client-server][trust-safety][report]")
{
    GIVEN("a running client-server with a logged-in user, a room, and a message")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);
        auto const room_id = create_room(started.runtime, token);
        auto const event_id = send_message(started.runtime, token, room_id);

        WHEN("the user sends a report with an invalid body")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/rooms/" + room_id + "/report/" + event_id, token, "this is not json"});

            THEN("the server returns 400 M_BAD_JSON")
            {
                // Spec: malformed JSON body -> 400.
                REQUIRE(response.response.status == 400U);
                auto const body = parse_object(response.response.body);
                REQUIRE(*string_member(body, "errcode") == "M_BAD_JSON");
            }
        }
    }
}

// Spec: Merovingian admin API
// Endpoint: GET /_matrix/client/v3/admin/safety/reports
//
// A server administrator MUST be able to list submitted safety reports.
SCENARIO("Admin GET /admin/safety/reports lists submitted reports", "[conformance][client-server][trust-safety][admin]")
{
    GIVEN("a running client-server with a report submitted by a user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const user_token = logged_in_token(started.runtime);
        auto const admin = admin_token(started.runtime);
        auto const room_id = create_room(started.runtime, user_token);
        auto const event_id = send_message(started.runtime, user_token, room_id);

        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    started.runtime, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/report/" + event_id, user_token,
                                      R"({"reason":"abuse"})"})
                    .response.status == 200U);

        WHEN("an admin requests the safety reports list")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/admin/safety/reports", admin, {}});

            THEN("the response is 200 and contains the submitted report")
            {
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* reports = object_member_as_array(body, "reports");
                REQUIRE(reports != nullptr);
                REQUIRE(!reports->empty());
            }
        }
    }
}
