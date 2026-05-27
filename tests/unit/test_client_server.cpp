// SPDX-License-Identifier: GPL-3.0-or-later

#include "../support/registration_token.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/client_server.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <string>

namespace
{

[[nodiscard]] auto registration_enabled_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    merovingian::tests::enable_token_registration(security);
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},
        security,
    };
}

[[nodiscard]] auto login_token(std::string const& body) -> std::string
{
    auto const key = std::string{"\"access_token\":\""};
    auto const begin = body.find(key);
    REQUIRE(begin != std::string::npos);
    auto const value_begin = begin + key.size();
    auto const value_end = body.find('"', value_begin);
    REQUIRE(value_end != std::string::npos);
    return body.substr(value_begin, value_end - value_begin);
}

[[nodiscard]] auto room_id(std::string const& body) -> std::string
{
    auto const key = std::string{"\"room_id\":\""};
    auto const begin = body.find(key);
    REQUIRE(begin != std::string::npos);
    auto const value_begin = begin + key.size();
    auto const value_end = body.find('"', value_begin);
    REQUIRE(value_end != std::string::npos);
    return body.substr(value_begin, value_end - value_begin);
}

[[nodiscard]] auto percent_encode_colons(std::string value) -> std::string
{
    auto pos = value.find(':');
    while (pos != std::string::npos)
    {
        value.replace(pos, 1U, "%3A");
        pos = value.find(':', pos + 3U);
    }
    return value;
}

[[nodiscard]] auto event_id(std::string const& body) -> std::string
{
    auto const key = std::string{"\"event_id\":\""};
    auto const begin = body.find(key);
    REQUIRE(begin != std::string::npos);
    auto const value_begin = begin + key.size();
    auto const value_end = body.find('"', value_begin);
    REQUIRE(value_end != std::string::npos);
    return body.substr(value_begin, value_end - value_begin);
}

[[nodiscard]] auto json_value(std::string const& body, std::string const& key) -> std::string
{
    auto const begin = body.find(key);
    REQUIRE(begin != std::string::npos);
    auto const value_begin = begin + key.size();
    auto const value_end = body.find('"', value_begin);
    REQUIRE(value_end != std::string::npos);
    return body.substr(value_begin, value_end - value_begin);
}

} // namespace

SCENARIO("Client-server runtime wraps errors in stable Matrix-style shapes", "[homeserver][client-server]")
{
    GIVEN("a Matrix error")
    {
        WHEN("it is rendered")
        {
            auto const body = merovingian::homeserver::matrix_error("M_FORBIDDEN", "denied");
            auto const response = merovingian::homeserver::LocalHttpResponse{403U, body};

            THEN("the response has a stable Matrix error body")
            {
                REQUIRE(body == R"({"errcode":"M_FORBIDDEN","error":"denied"})");
                REQUIRE(merovingian::homeserver::is_matrix_error_response(response));
            }
        }
    }
}

SCENARIO("Client-server runtime exposes production-named start and flow APIs", "[homeserver][client-server]")
{
    GIVEN("registration-enabled client-server configuration")
    {
        auto const config = registration_enabled_config();

        WHEN("the production client-server runtime and flow APIs are used")
        {
            auto started = merovingian::homeserver::start_client_server(config);
            auto const flow = merovingian::homeserver::run_client_server_flow(config);

            THEN("the runtime starts and the safe client-server flow completes")
            {
                REQUIRE(started.started);
                REQUIRE(flow.ok);
                REQUIRE(flow.value.find("next_batch") != std::string::npos);
                REQUIRE(flow.value.find("secret") == std::string::npos);
            }
        }
    }
}

SCENARIO("Client-server runtime account and device endpoints use real sessions", "[homeserver][client-server]")
{
    GIVEN("a started client-server runtime")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("a user registers and logs in")
        {
            auto const registered = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST",
                          "/_matrix/client/v3/register",
                          {},
                          merovingian::tests::registration_json("alice", "CorrectHorse7!")});
            auto const login = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST",
                 "/_matrix/client/v3/login",
                 {},
                 R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
            auto const token = login_token(login.response.body);
            auto const whoami = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/account/whoami", token, {}});
            auto const devices = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/devices", token, {}});
            auto const update = merovingian::homeserver::handle_client_server_request(
                runtime, {"PUT", "/_matrix/client/v3/devices/DEVICE1", token, R"({"display_name":"Alice laptop"})"});
            auto const updated_devices = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/devices", token, {}});

            THEN("identity, device listing, and device updates work through token validation")
            {
                REQUIRE(registered.response.status == 200U);
                REQUIRE(login.response.status == 200U);
                REQUIRE(whoami.response.status == 200U);
                REQUIRE(whoami.response.body.find("@alice:example.org") != std::string::npos);
                REQUIRE(devices.response.status == 200U);
                REQUIRE(devices.response.body.find("DEVICE1") != std::string::npos);
                REQUIRE(update.response.status == 200U);
                REQUIRE(updated_devices.response.body.find("Alice laptop") != std::string::npos);
                REQUIRE(merovingian::homeserver::device_count(runtime, "@alice:example.org") == 1U);
            }
        }
    }
}

SCENARIO("Client-server runtime rejects malformed Matrix JSON request bodies", "[homeserver][client-server]")
{
    GIVEN("a started client-server runtime")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("registration and login receive malformed or incomplete JSON")
        {
            auto const malformed_registration = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/register", {}, R"({"username":"alice","password":)"});
            auto const incomplete_login = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST",
                 "/_matrix/client/v3/login",
                 {},
                 R"({"type":"m.login.password","password":"CorrectHorse7!","auth":{"type":"m.login.registration_token","token":"test-registration-token"}})"});

            THEN("the API fails closed with stable Matrix bad-json errors")
            {
                REQUIRE(malformed_registration.response.status == 400U);
                REQUIRE(incomplete_login.response.status == 400U);
                REQUIRE(malformed_registration.response.body.find("M_BAD_JSON") != std::string::npos);
                REQUIRE(incomplete_login.response.body.find("M_BAD_JSON") != std::string::npos);
            }
        }
    }
}

SCENARIO("Client-server runtime dispatches complete HTTP requests through Matrix JSON handlers",
         "[homeserver][client-server][http]")
{
    GIVEN("a started client-server runtime")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("registration login and whoami arrive as raw HTTP requests")
        {
            auto const registration_body =
                std::string{merovingian::tests::registration_json("alice", "CorrectHorse7!")};
            auto const registration = merovingian::homeserver::handle_client_server_http_request(
                runtime, "POST /_matrix/client/v3/register HTTP/1.1\r\nHost: example.org\r\nContent-Length: " +
                             std::to_string(registration_body.size()) + "\r\n\r\n" + registration_body);
            auto const login_body = std::string{
                R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"};
            auto const login = merovingian::homeserver::handle_client_server_http_request(
                runtime, "POST /_matrix/client/v3/login HTTP/1.1\r\nHost: example.org\r\nContent-Length: " +
                             std::to_string(login_body.size()) + "\r\n\r\n" + login_body);
            auto const token = login_token(login.body);
            auto const whoami = merovingian::homeserver::handle_client_server_http_request(
                runtime,
                "GET /_matrix/client/v3/account/whoami HTTP/1.1\r\nHost: example.org\r\nAuthorization: Bearer " +
                    token + "\r\nContent-Length: 0\r\n\r\n");

            THEN("the HTTP adapter preserves Matrix status bodies and bearer auth")
            {
                REQUIRE(registration.status == 200U);
                REQUIRE(login.status == 200U);
                REQUIRE(whoami.status == 200U);
                REQUIRE(whoami.body.find("@alice:example.org") != std::string::npos);
            }
        }
    }
}

SCENARIO("Client-server runtime HTTP adapter rejects incomplete and trailing request bodies",
         "[homeserver][client-server][http]")
{
    GIVEN("a started client-server runtime")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("raw HTTP requests do not match their declared content length")
        {
            auto const incomplete = merovingian::homeserver::handle_client_server_http_request(
                runtime,
                "POST /_matrix/client/v3/register HTTP/1.1\r\nHost: example.org\r\nContent-Length: 12\r\n\r\n{}");
            auto const trailing = merovingian::homeserver::handle_client_server_http_request(
                runtime,
                "GET /_matrix/client/v3/account/whoami HTTP/1.1\r\nHost: example.org\r\nContent-Length: 0\r\n\r\nx");

            THEN("the adapter fails closed before route dispatch")
            {
                REQUIRE(incomplete.status == 400U);
                REQUIRE(trailing.status == 400U);
                REQUIRE(incomplete.body.find("M_BAD_REQUEST") != std::string::npos);
                REQUIRE(trailing.body.find("M_BAD_REQUEST") != std::string::npos);
            }
        }
    }
}

SCENARIO("Client-server GET login returns password flow discovery response", "[homeserver][client-server]")
{
    GIVEN("a running client-server homeserver")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("an unauthenticated client queries GET /_matrix/client/v3/login")
        {
            auto const resp = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/login", {}, {}});

            THEN("the server returns 200 with a flows array containing m.login.password")
            {
                REQUIRE(resp.response.status == 200U);
                REQUIRE(resp.response.body.find("\"flows\"") != std::string::npos);
                REQUIRE(resp.response.body.find("\"m.login.password\"") != std::string::npos);
            }
        }
    }
}

SCENARIO("Client-server runtime escapes login and device JSON strings", "[homeserver][client-server]")
{
    GIVEN("a logged-in client-server user with a device value requiring JSON escapes")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("alice", "CorrectHorse7!")})
                    .response.status == 200U);

        WHEN("the device id and display name include quotes and backslashes")
        {
            auto const login = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST",
                 "/_matrix/client/v3/login",
                 {},
                 R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEV\"\\ICE"})"});
            auto const token = login_token(login.response.body);
            auto const update = merovingian::homeserver::handle_client_server_request(
                runtime, {"PUT", R"(/_matrix/client/v3/devices/DEV"\ICE)", token,
                          R"({"display_name":"Alice \"Laptop\" \\ 1"})"});
            auto const devices = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/devices", token, {}});

            THEN("login and device responses remain valid escaped JSON strings")
            {
                REQUIRE(login.response.status == 200U);
                REQUIRE(login.response.body.find(R"("device_id":"DEV\"\\ICE")") != std::string::npos);
                REQUIRE(update.response.status == 200U);
                REQUIRE(devices.response.status == 200U);
                REQUIRE(devices.response.body.find(R"("device_id":"DEV\"\\ICE")") != std::string::npos);
                REQUIRE(devices.response.body.find(R"("display_name":"Alice \"Laptop\" \\ 1")") != std::string::npos);
            }
        }
    }
}

SCENARIO("Client-server runtime room state joined rooms and sync endpoints compose the homeserver path",
         "[homeserver][client-server]")
{
    GIVEN("a logged-in client-server user")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("alice", "CorrectHorse7!")})
                    .response.status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = login_token(login.response.body);

        WHEN("the user creates a room, sends encrypted-looking content, and syncs")
        {
            auto const room = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/createRoom", token, {}});
            auto const id = room_id(room.response.body);
            auto const send = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/rooms/" + id + "/send", token,
                          R"({"type":"m.room.encrypted","content":"secret"})"});
            auto const state = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/rooms/" + id + "/state", token, {}});
            auto const joined = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/joined_rooms", token, {}});
            auto const sync = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/sync", token, {}});

            THEN("room and sync responses are bounded summaries without plaintext event content")
            {
                REQUIRE(room.response.status == 200U);
                REQUIRE(send.response.status == 200U);
                REQUIRE(state.response.status == 200U);
                REQUIRE(joined.response.status == 200U);
                REQUIRE(joined.response.body.find(id) != std::string::npos);
                REQUIRE(sync.response.status == 200U);
                REQUIRE(sync.response.body.find(id) != std::string::npos);
                REQUIRE(sync.response.body.find("event_count") != std::string::npos);
                REQUIRE(sync.response.body.find("secret") == std::string::npos);
                REQUIRE(sync.response.body.find("m.room.encrypted") == std::string::npos);
                REQUIRE(merovingian::homeserver::joined_room_count(runtime, "@alice:example.org") == 1U);
            }
        }
    }
}

SCENARIO("Client-server publicRooms lists local public-chat rooms instead of returning M_UNRECOGNIZED",
         "[homeserver][client-server][public-rooms]")
{
    GIVEN("a started runtime with one private room and one public room")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("alice", "CorrectHorse7!")})
                    .response.status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = login_token(login.response.body);

        auto const private_room = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v3/createRoom", token, R"({"name":"Private room"})"});
        REQUIRE(private_room.response.status == 200U);
        auto const private_room_id = room_id(private_room.response.body);

        auto const public_room = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v3/createRoom", token,
                      R"({"preset":"public_chat","name":"Lobby","topic":"Open to everyone"})"});
        REQUIRE(public_room.response.status == 200U);
        auto const public_room_id = room_id(public_room.response.body);

        WHEN("the client requests GET /_matrix/client/v3/publicRooms with a server query parameter")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/publicRooms?server=example.org", {}, {}});

            THEN("the response is 200 and lists only the public room in the chunk")
            {
                REQUIRE(response.response.status == 200U);
                REQUIRE(response.response.body.find("\"chunk\"") != std::string::npos);
                REQUIRE(response.response.body.find(public_room_id) != std::string::npos);
                REQUIRE(response.response.body.find(private_room_id) == std::string::npos);
                REQUIRE(response.response.body.find("\"name\":\"Lobby\"") != std::string::npos);
                REQUIRE(response.response.body.find("\"topic\":\"Open to everyone\"") != std::string::npos);
                REQUIRE(response.response.body.find("\"join_rule\":\"public\"") != std::string::npos);
                REQUIRE(response.response.body.find("\"world_readable\":true") != std::string::npos);
            }
        }
    }
}

SCENARIO("Client-server im.nheko.summary endpoints return room membership summaries",
         "[homeserver][client-server][nheko-summary]")
{
    GIVEN("a logged-in user with a created room")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("alice", "CorrectHorse7!")})
                    .response.status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = login_token(login.response.body);
        auto const room = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v3/createRoom", token, {}});
        REQUIRE(room.response.status == 200U);
        auto const id = room_id(room.response.body);

        WHEN("the user requests the nheko summary for the room")
        {
            auto const encoded = percent_encode_colons(id);
            auto const summary_short = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/unstable/im.nheko.summary/summary/" + encoded, token, {}});
            auto const summary_long = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/unstable/im.nheko.summary/rooms/" + encoded + "/summary", token, {}});
            auto const summary_missing = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/unstable/im.nheko.summary/summary/!missing:example.org", token, {}});

            THEN("both path shapes return 200 with room_id and summary; missing rooms return 404")
            {
                REQUIRE(summary_short.response.status == 200U);
                REQUIRE(summary_short.response.body.find(id) != std::string::npos);
                REQUIRE(summary_short.response.body.find("m.joined_member_count") != std::string::npos);
                REQUIRE(summary_long.response.status == 200U);
                REQUIRE(summary_long.response.body.find(id) != std::string::npos);
                REQUIRE(summary_long.response.body.find("m.joined_member_count") != std::string::npos);
                REQUIRE(summary_missing.response.status == 404U);
            }
        }
    }
}

SCENARIO("Client-server typing and messages routes dispatch through the room block",
         "[homeserver][client-server][typing][messages]")
{
    GIVEN("a logged-in user with a created room")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("alice", "CorrectHorse7!")})
                    .response.status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = login_token(login.response.body);
        auto const room = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v3/createRoom", token, {}});
        REQUIRE(room.response.status == 200U);
        auto const id = room_id(room.response.body);

        WHEN("the user sets typing state for themselves")
        {
            auto const typing = merovingian::homeserver::handle_client_server_request(
                runtime, {"PUT", "/_matrix/client/v3/rooms/" + id + "/typing/@alice:example.org", token,
                          R"({"typing":true,"timeout":3000})"});

            THEN("the request is accepted")
            {
                REQUIRE(typing.response.status == 200U);
            }
        }

        WHEN("the user tries to set typing state for another user")
        {
            auto const typing = merovingian::homeserver::handle_client_server_request(
                runtime, {"PUT", "/_matrix/client/v3/rooms/" + id + "/typing/@mallory:example.org", token,
                          R"({"typing":true})"});

            THEN("the request is rejected with 403 M_FORBIDDEN")
            {
                REQUIRE(typing.response.status == 403U);
                REQUIRE(typing.response.body.find("M_FORBIDDEN") != std::string::npos);
            }
        }

        WHEN("the user requests messages from their room")
        {
            auto const messages = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/rooms/" + id + "/messages?dir=b&limit=10", token, {}});

            THEN("the response carries chunk, start, end, and state fields")
            {
                REQUIRE(messages.response.status == 200U);
                REQUIRE(messages.response.body.find("chunk") != std::string::npos);
                REQUIRE(messages.response.body.find("start") != std::string::npos);
                REQUIRE(messages.response.body.find("end") != std::string::npos);
                REQUIRE(messages.response.body.find("state") != std::string::npos);
            }
        }

        WHEN("the user requests messages from a non-existent room")
        {
            auto const messages = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/rooms/!nonexistent:example.org/messages", token, {}});

            THEN("the response is 404 M_NOT_FOUND")
            {
                REQUIRE(messages.response.status == 404U);
                REQUIRE(messages.response.body.find("M_NOT_FOUND") != std::string::npos);
            }
        }
    }
}

SCENARIO("Client-server leave and read_markers routes", "[homeserver][client-server][leave][read_markers]")
{
    GIVEN("a logged-in user with a created room")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("alice", "CorrectHorse7!")})
                    .response.status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = login_token(login.response.body);
        auto const room = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v3/createRoom", token, {}});
        REQUIRE(room.response.status == 200U);
        auto const id = room_id(room.response.body);

        WHEN("the user posts read_markers for their room")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/rooms/" + id + "/read_markers", token,
                          R"({"m.fully_read":"$event1","m.read":"$event1"})"});

            THEN("the response is 200 with an empty object body")
            {
                REQUIRE(response.response.status == 200U);
            }
        }

        WHEN("the user leaves their room")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/rooms/" + id + "/leave", token, "{}"});

            THEN("the response is 200 and the room no longer appears in joined_rooms")
            {
                REQUIRE(response.response.status == 200U);
                auto const rooms_resp = merovingian::homeserver::handle_client_server_request(
                    runtime, {"GET", "/_matrix/client/v3/joined_rooms", token, {}});
                REQUIRE(rooms_resp.response.body.find(id) == std::string::npos);
            }
        }

        WHEN("the user tries to leave a non-existent room")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/rooms/!nonexistent:example.org/leave", token, "{}"});

            THEN("the response is 404 M_NOT_FOUND")
            {
                REQUIRE(response.response.status == 404U);
                REQUIRE(response.response.body.find("M_NOT_FOUND") != std::string::npos);
            }
        }

        WHEN("a non-member tries to leave the room")
        {
            // Register a second user who never joined the room
            REQUIRE(merovingian::homeserver::handle_client_server_request(
                        runtime, {"POST",
                                  "/_matrix/client/v3/register",
                                  {},
                                  merovingian::tests::registration_json("bob", "CorrectHorse7!")})
                        .response.status == 200U);
            auto const bob_login = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST",
                 "/_matrix/client/v3/login",
                 {},
                 R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@bob:example.org"},"password":"CorrectHorse7!","device_id":"BOBDEV"})"});
            REQUIRE(bob_login.response.status == 200U);
            auto const bob_token = login_token(bob_login.response.body);

            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/rooms/" + id + "/leave", bob_token, "{}"});

            THEN("the response is 403 M_FORBIDDEN")
            {
                REQUIRE(response.response.status == 403U);
                REQUIRE(response.response.body.find("M_FORBIDDEN") != std::string::npos);
            }
        }
    }
}

SCENARIO("Client-server runtime signs sent events and persists their DAG metadata",
         "[homeserver][client-server][events]")
{
    GIVEN("a logged-in client-server user with a room")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("alice", "CorrectHorse7!")})
                    .response.status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = login_token(login.response.body);
        auto const room = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v3/createRoom", token, {}});
        auto const id = room_id(room.response.body);

        WHEN("state and message events are sent through the runtime")
        {
            auto const state = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST", "/_matrix/client/v3/rooms/" + id + "/send", token,
                 R"({"type":"m.room.member","state_key":"@alice:example.org","content":{"membership":"join"}})"});
            auto const message = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/rooms/" + id + "/send", token,
                          R"({"type":"m.room.message","content":{"body":"hi","msgtype":"m.text"}})"});
            auto const& store = runtime.homeserver.database.persistent_store;
            auto const state_event_id = event_id(state.response.body);
            auto const message_event_id = event_id(message.response.body);

            THEN("the returned event IDs are reference hashes and persisted rows include signatures and DAG edges")
            {
                REQUIRE(state.response.status == 200U);
                REQUIRE(message.response.status == 200U);
                REQUIRE(state_event_id.starts_with("$"));
                REQUIRE(message_event_id.starts_with("$"));
                REQUIRE(state_event_id.find(":") == std::string::npos);
                REQUIRE(message_event_id.find(":") == std::string::npos);
                REQUIRE(store.server_signing_keys.size() == 1U);
                // create_room emits 4 initial state events (create, member,
                // power_levels, join_rules); the client-server handler adds
                // history_visibility (join_rules is skipped for the default
                // "invite" preset) = 5 from createRoom, plus the member state
                // and message sent in this scenario = 7.
                REQUIRE(store.events.size() == 7U);
                REQUIRE(store.events.back().json.find("\"hashes\"") != std::string::npos);
                REQUIRE(store.events.back().json.find("\"signatures\"") != std::string::npos);
                REQUIRE(store.event_signatures.size() == store.events.size());

                // The message event links back to the member state event sent
                // immediately before it and records at least one auth edge.
                auto message_prev_event_id = std::string{};
                auto message_has_auth_edge = false;
                for (auto const& edge : store.event_edges)
                {
                    if (edge.event_id == message_event_id)
                    {
                        message_prev_event_id = edge.prev_event_id;
                    }
                }
                for (auto const& auth_edge : store.event_auth)
                {
                    if (auth_edge.event_id == message_event_id)
                    {
                        message_has_auth_edge = true;
                    }
                }
                REQUIRE(message_prev_event_id == state_event_id);
                REQUIRE(message_has_auth_edge);
            }
        }
    }
}

SCENARIO("Client-server runtime wires server-blind E2EE key API routes", "[homeserver][client-server][key-api]")
{
    GIVEN("a logged-in client-server device")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("alice", "CorrectHorse7!")})
                    .response.status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = login_token(login.response.body);

        WHEN("the device uploads server-blind key material and queries keys")
        {
            auto const upload = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/keys/upload", token,
                          R"({"device_keys":{"sensitive":"curve25519-secret"},"one_time_keys":{}})"});
            auto const query = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/keys/query", token,
                          R"({"device_keys":{"@alice:example.org":["DEVICE1"]}})"});
            auto const unauthenticated = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/keys/upload", {}, R"({"device_keys":{}})"});

            THEN("the runtime path accepts the route without exposing key payloads")
            {
                REQUIRE(upload.response.status == 200U);
                REQUIRE(query.response.status == 200U);
                REQUIRE(unauthenticated.response.status == 401U);
                REQUIRE(upload.response.body.find("one_time_key_counts") != std::string::npos);
                REQUIRE(query.response.body.find("device_keys") != std::string::npos);
                REQUIRE(upload.response.body.find("curve25519-secret") == std::string::npos);
                REQUIRE(merovingian::homeserver::key_api_record_count(runtime, "@alice:example.org") == 2U);
            }
        }
    }
}

SCENARIO("Client-server runtime wires trust and safety report and admin review routes",
         "[homeserver][client-server][trust-safety]")
{
    GIVEN("a logged-in admin client-server user")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const admin = merovingian::homeserver::bootstrap_admin_user(runtime.homeserver, "alice", "CorrectHorse7!");
        REQUIRE(admin.ok);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = login_token(login.response.body);

        WHEN("the client reports an event and the admin reviews a media target")
        {
            auto const report = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/rooms/!room:example.org/report/$event", token,
                          R"({"reason":"spam","score":50})"});
            auto const reports = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/admin/safety/reports", token, {}});
            auto const review = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/admin/safety/review/media/media123", token,
                          R"({"reason":"manual_review"})"});

            THEN("policy decisions are served through runtime auth and persisted as audit/admin rows")
            {
                REQUIRE(report.response.status == 200U);
                REQUIRE(reports.response.status == 200U);
                REQUIRE(review.response.status == 200U);
                REQUIRE(reports.response.body.find("trust_safety.room.accept_report") != std::string::npos);
                REQUIRE(runtime.homeserver.database.persistent_store.audit_log.size() >= 4U);
                REQUIRE(runtime.homeserver.database.persistent_store.admin_actions.size() == 1U);
                REQUIRE(runtime.homeserver.database.persistent_store.admin_actions.front().action ==
                        "trust_safety.media.quarantine");
            }
        }
    }
}

SCENARIO("Client-server runtime persists client action audit events", "[homeserver][client-server][audit]")
{
    GIVEN("a logged-in client-server device")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("alice", "CorrectHorse7!")})
                    .response.status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = login_token(login.response.body);

        WHEN("the device updates metadata and uploads E2EE keys")
        {
            auto const update = merovingian::homeserver::handle_client_server_request(
                runtime, {"PUT", "/_matrix/client/v3/devices/DEVICE1", token, R"({"display_name":"Alice laptop"})"});
            auto const upload = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/keys/upload", token, R"({"device_keys":{"secret":"value"}})"});

            THEN("client-server audit events are durable and redact key payloads")
            {
                REQUIRE(update.response.status == 200U);
                REQUIRE(upload.response.status == 200U);
                auto const& audit = runtime.homeserver.database.persistent_store.audit_log;
                REQUIRE(audit.size() >= 4U);
                REQUIRE(std::ranges::any_of(audit, [](auto const& event) {
                    return event.event_type == "device.updated";
                }));
                REQUIRE(std::ranges::any_of(audit, [](auto const& event) {
                    return event.event_type == "key_api.upload_keys" &&
                           event.reason.find("secret") == std::string::npos;
                }));
            }
        }
    }
}

SCENARIO("Client-server runtime enforces request limits and Matrix-style errors", "[homeserver][client-server]")
{
    GIVEN("a started client-server runtime with tight limits")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        runtime.limits.max_body_bytes = 4U;
        runtime.limits.max_requests_per_bucket = 1U;
        runtime.limits.rate_limit_window_requests = 64U;

        WHEN("oversized and repeated requests are sent")
        {
            auto const oversized = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST",
                          "/_matrix/client/v3/register",
                          {},
                          merovingian::tests::registration_pipe("alice", "CorrectHorse7!")});
            runtime.limits.max_body_bytes = 65536U;
            auto const first = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/account/whoami", "bad", {}});
            auto const second = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/account/whoami", "bad", {}});

            THEN("the client-server API reports stable bounded errors")
            {
                REQUIRE(oversized.response.status == 413U);
                REQUIRE(merovingian::homeserver::is_matrix_error_response(oversized.response));
                REQUIRE(first.response.status == 401U);
                REQUIRE(merovingian::homeserver::is_matrix_error_response(first.response));
                REQUIRE(second.response.status == 429U);
                REQUIRE(merovingian::homeserver::is_matrix_error_response(second.response));
            }
        }
    }
}

SCENARIO("Client-server runtime normalizes route-template rate-limit buckets", "[homeserver][client-server]")
{
    GIVEN("a started client-server runtime with a one-request route bucket")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        runtime.limits.max_requests_per_bucket = 1U;
        runtime.limits.rate_limit_window_requests = 64U;

        WHEN("different room IDs hit the same route template")
        {
            auto const first = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/rooms/!one:example.org/send", "bad", "{}"});
            auto const second = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/rooms/!two:example.org/send", "bad", "{}"});

            THEN("the second request is limited by the normalized route bucket")
            {
                REQUIRE(first.response.status == 401U);
                REQUIRE(second.response.status == 429U);
                REQUIRE(runtime.rate_limits.size() == 1U);
            }
        }
    }
}

SCENARIO("Client-server runtime rate-limit buckets reset after the logical window", "[homeserver][client-server]")
{
    GIVEN("a started client-server runtime with a short rate-limit window")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        runtime.limits.max_requests_per_bucket = 1U;
        runtime.limits.rate_limit_window_requests = 2U;

        WHEN("a bucket is exhausted and the logical request window advances")
        {
            auto const first = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/account/whoami", "bad", {}});
            auto const limited = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/account/whoami", "bad", {}});
            auto const reset = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/account/whoami", "bad", {}});

            THEN("the bucket becomes available again after the reset window")
            {
                REQUIRE(first.response.status == 401U);
                REQUIRE(limited.response.status == 429U);
                REQUIRE(reset.response.status == 401U);
            }
        }
    }
}

SCENARIO("Sync endpoint returns stream token and event bodies for initial and incremental sync",
         "[homeserver][client-server][sync]")
{
    GIVEN("a logged-in user with a room and a sent event")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const registered = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST",
                      "/_matrix/client/v3/register",
                      {},
                      merovingian::tests::registration_json("alice", "CorrectHorse7!")});
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        auto const token = login_token(login.response.body);
        auto const room = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v3/createRoom", token, {}});
        auto const room_id = json_value(room.response.body, "\"room_id\":\"");
        auto const send = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/send", token,
                      R"({"type":"m.room.message","content":{"body":"hello","msgtype":"m.text"}})"});

        WHEN("initial sync is requested without a since token")
        {
            auto const sync = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/sync", token, {}});

            THEN("the response contains a stream token next_batch and event bodies in the timeline")
            {
                REQUIRE(sync.response.status == 200U);
                REQUIRE(sync.response.body.find("\"next_batch\"") != std::string::npos);
                REQUIRE(sync.response.body.find("\"events\":") != std::string::npos);
                REQUIRE(sync.response.body.find("\"timeline\"") != std::string::npos);
                REQUIRE(sync.response.body.find("\"rooms\"") != std::string::npos);
            }
        }

        WHEN("incremental sync is requested with the stream token from initial sync")
        {
            auto const initial = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/sync", token, {}});
            auto const since_token = json_value(initial.response.body, "\"next_batch\":\"");

            auto const incremental = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/sync?since=" + since_token, token, {}});

            THEN("the incremental response contains a new stream token and no duplicate events")
            {
                REQUIRE(incremental.response.status == 200U);
                REQUIRE(incremental.response.body.find("\"next_batch\"") != std::string::npos);
                REQUIRE(incremental.response.body.find("\"rooms\"") != std::string::npos);
            }
        }
    }
}

SCENARIO("Client-server /versions advertises Matrix spec compatibility to unauthenticated clients",
         "[homeserver][client-server][versions]")
{
    GIVEN("a started client-server runtime")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto runtime = std::move(started.runtime);

        WHEN("an unauthenticated client requests GET /_matrix/client/versions")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/versions", {}, {}});

            THEN("the server answers 200 with a versions array and unstable_features object")
            {
                REQUIRE(response.response.status == 200U);
                REQUIRE(response.response.body.find("\"versions\"") != std::string::npos);
                REQUIRE(response.response.body.find("\"v1.18\"") != std::string::npos);
                REQUIRE(response.response.body.find("\"v1.1\"") != std::string::npos);
                REQUIRE(response.response.body.find("\"unstable_features\"") != std::string::npos);
                REQUIRE_FALSE(merovingian::homeserver::is_matrix_error_response(response.response));
            }
        }
    }
}

SCENARIO("Sync surfaces invite and leave room categories alongside Matrix-spec top-level stubs",
         "[homeserver][client-server][sync]")
{
    GIVEN("a registered user with an outstanding invite and a left room")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto runtime = std::move(started.runtime);

        auto const register_response = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST",
                      "/_matrix/client/v3/register",
                      {},
                      merovingian::tests::registration_json("alice", "CorrectHorse7!")});
        REQUIRE(register_response.response.status == 200U);
        auto const user_id = json_value(register_response.response.body, "\"user_id\":\"");

        auto const login_response = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST",
                      "/_matrix/client/v3/login",
                      {},
                      R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":")" + user_id +
                          R"("},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login_response.response.status == 200U);
        auto const token = login_token(login_response.response.body);

        runtime.homeserver.database.persistent_store.memberships.push_back(
            {"!invited_room:example.org", user_id, "invite", 0U});
        runtime.homeserver.database.persistent_store.memberships.push_back(
            {"!left_room:example.org", user_id, "leave", 0U});

        WHEN("the user requests /sync")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/sync", token, {}});

            THEN("the response carries the invite room category and Matrix-spec top-level keys")
            {
                REQUIRE(response.response.status == 200U);
                REQUIRE(response.response.body.find("\"invite\"") != std::string::npos);
                REQUIRE(response.response.body.find("!invited_room:example.org") != std::string::npos);
                REQUIRE(response.response.body.find("\"invite_state\"") != std::string::npos);
                REQUIRE(response.response.body.find("\"account_data\"") != std::string::npos);
                REQUIRE(response.response.body.find("\"presence\"") != std::string::npos);
                REQUIRE(response.response.body.find("\"to_device\"") != std::string::npos);
                REQUIRE(response.response.body.find("\"device_lists\"") != std::string::npos);
                REQUIRE(response.response.body.find("\"device_one_time_keys_count\"") != std::string::npos);
            }

            THEN("the response keeps rooms.leave as an empty object until include_leave filter support lands")
            {
                REQUIRE(response.response.body.find("\"leave\":{}") != std::string::npos);
                REQUIRE(response.response.body.find("!left_room:example.org") == std::string::npos);
            }
        }

        WHEN("the user has more invite memberships than max_sync_rooms")
        {
            runtime.limits.max_sync_rooms = 2U;
            runtime.homeserver.database.persistent_store.memberships.push_back(
                {"!invite2:example.org", user_id, "invite", 0U});
            runtime.homeserver.database.persistent_store.memberships.push_back(
                {"!invite3:example.org", user_id, "invite", 0U});
            runtime.homeserver.database.persistent_store.memberships.push_back(
                {"!invite4:example.org", user_id, "invite", 0U});

            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/sync", token, {}});

            THEN("the invite section honors the room cap and does not bloat the response")
            {
                REQUIRE(response.response.status == 200U);
                // First two invites in iteration order should be present
                // (the originally pushed `!invited_room` plus `!invite2`);
                // later invites must be dropped by the cap.
                REQUIRE(response.response.body.find("!invited_room:example.org") != std::string::npos);
                REQUIRE(response.response.body.find("!invite2:example.org") != std::string::npos);
                REQUIRE(response.response.body.find("!invite3:example.org") == std::string::npos);
                REQUIRE(response.response.body.find("!invite4:example.org") == std::string::npos);
            }
        }
    }
}

SCENARIO("Client-server enforces per-endpoint rate limits with 429 M_LIMIT_EXCEEDED",
         "[homeserver][client-server][rate-limit]")
{
    GIVEN("a started client-server runtime")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto runtime = std::move(started.runtime);

        WHEN("registration is invoked more times than the endpoint policy allows in the window")
        {
            // endpoint_default_rate_limit returns {max_requests=5, window_seconds=60}
            // for POST /_matrix/client/v3/register, so the sixth request inside
            // the wall-clock window must fail closed.
            auto last_status = std::uint16_t{0U};
            auto last_body = std::string{};
            for (auto index = 0; index < 6; ++index)
            {
                auto body = std::string{"{\"username\":\"user"};
                body += std::to_string(index);
                body += "\",\"password\":\"CorrectHorse7!\"}";
                auto const response = merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST", "/_matrix/client/v3/register", {}, body});
                last_status = response.response.status;
                last_body = response.response.body;
            }

            THEN("the sixth attempt fails closed with 429 and M_LIMIT_EXCEEDED")
            {
                REQUIRE(last_status == 429U);
                REQUIRE(last_body.find("M_LIMIT_EXCEEDED") != std::string::npos);
            }
        }

        WHEN("an unrelated endpoint is hit after exhausting registration's quota")
        {
            for (auto index = 0; index < 6; ++index)
            {
                auto body = std::string{"{\"username\":\"flood"};
                body += std::to_string(index);
                body += "\",\"password\":\"CorrectHorse7!\"}";
                static_cast<void>(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST", "/_matrix/client/v3/register", {}, body}));
            }

            auto const versions_response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/versions", {}, {}});

            THEN("the other endpoint runs on its own bucket and is not rate-limited")
            {
                REQUIRE(versions_response.response.status == 200U);
                REQUIRE_FALSE(merovingian::homeserver::is_matrix_error_response(versions_response.response));
            }
        }
    }
}

SCENARIO("Rate-limit buckets are scoped per access token to prevent cross-user denial of service",
         "[homeserver][client-server][rate-limit]")
{
    GIVEN("a started runtime with two registered, logged-in users")
    {
        // Register and log in both users with the default loose cap so the
        // setup itself does not collide with the bucket. The tight per-user
        // cap is applied after both users hold valid access tokens.
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const register_alice = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST",
                      "/_matrix/client/v3/register",
                      {},
                      merovingian::tests::registration_json("alice", "CorrectHorse7!")});
        REQUIRE(register_alice.response.status == 200U);
        auto const register_bob = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST",
                      "/_matrix/client/v3/register",
                      {},
                      merovingian::tests::registration_json("bob", "CorrectHorse7!")});
        REQUIRE(register_bob.response.status == 200U);

        auto const login_alice = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login_alice.response.status == 200U);
        auto const alice_token = login_token(login_alice.response.body);

        auto const login_bob = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@bob:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login_bob.response.status == 200U);
        auto const bob_token = login_token(login_bob.response.body);

        runtime.limits.max_requests_per_bucket = 1U;
        runtime.limits.rate_limit_window_requests = 64U;

        WHEN("alice exhausts her authenticated bucket")
        {
            auto const alice_first = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/account/whoami", alice_token, {}});
            auto const alice_second = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/account/whoami", alice_token, {}});
            auto const bob_first = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/account/whoami", bob_token, {}});

            THEN("alice's second request is 429 but bob's first request runs on his own bucket and succeeds")
            {
                REQUIRE(alice_first.response.status == 200U);
                REQUIRE(alice_second.response.status == 429U);
                REQUIRE(merovingian::homeserver::is_matrix_error_response(alice_second.response));
                REQUIRE(bob_first.response.status == 200U);
            }
        }
    }
}

SCENARIO("Login failures return HTTP 403 M_FORBIDDEN per the Matrix spec", "[homeserver][client-server][login][auth]")
{
    GIVEN("a started client-server runtime with registration enabled")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("login is attempted for a user that does not exist")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST",
                 "/_matrix/client/v3/login",
                 {},
                 R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@nobody:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});

            THEN("the response is 403 M_FORBIDDEN, not 400")
            {
                REQUIRE(response.response.status == 403U);
                REQUIRE(response.response.body.find("M_FORBIDDEN") != std::string::npos);
            }
        }

        WHEN("a user registers and then logs in with the wrong password")
        {
            auto const registered = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST",
                          "/_matrix/client/v3/register",
                          {},
                          merovingian::tests::registration_json("alice", "CorrectHorse7!")});
            REQUIRE(registered.response.status == 200U);

            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST",
                 "/_matrix/client/v3/login",
                 {},
                 R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"WrongPassword1!","device_id":"DEVICE1"})"});

            THEN("the response is 403 M_FORBIDDEN, not 400")
            {
                REQUIRE(response.response.status == 403U);
                REQUIRE(response.response.body.find("M_FORBIDDEN") != std::string::npos);
            }
        }
    }
}

SCENARIO("OPTIONS preflight requests return 200 without requiring an access token",
         "[homeserver][client-server][cors][preflight]")
{
    GIVEN("a started client-server runtime")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("an OPTIONS preflight is sent to the login endpoint without an access token")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"OPTIONS", "/_matrix/client/v3/login", {}, {}});

            THEN("the response is 200, not 401, so the browser allows the following POST")
            {
                REQUIRE(response.response.status == 200U);
            }
        }

        WHEN("an OPTIONS preflight is sent to the register endpoint without an access token")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"OPTIONS", "/_matrix/client/v3/register", {}, {}});

            THEN("the response is 200")
            {
                REQUIRE(response.response.status == 200U);
            }
        }
    }
}

SCENARIO("Well-known client discovery endpoint serves homeserver base URL",
         "[homeserver][client-server][well-known][discovery]")
{
    GIVEN("a started client-server runtime with a configured public base URL")
    {
        auto server = merovingian::config::ServerConfig{};
        server.public_baseurl = "https://matrix.example.org";
        auto security = merovingian::config::SecurityConfig{};
        merovingian::tests::enable_token_registration(security);
        auto config = merovingian::config::Config{server, {}, {}, security};
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("GET /.well-known/matrix/client is requested")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/.well-known/matrix/client", {}, {}});

            THEN("the response is 200 with the homeserver base URL in the Matrix discovery format")
            {
                REQUIRE(response.response.status == 200U);
                REQUIRE(response.response.body.find("m.homeserver") != std::string::npos);
                REQUIRE(response.response.body.find("https://matrix.example.org") != std::string::npos);
                REQUIRE(response.response.body.find("base_url") != std::string::npos);
            }
        }
    }
}

SCENARIO("Capabilities endpoint returns server feature flags for authenticated clients",
         "[homeserver][client-server][capabilities]")
{
    GIVEN("a started runtime with a registered and logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const reg = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST",
                      "/_matrix/client/v3/register",
                      {},
                      merovingian::tests::registration_json("alice", "CorrectHorse7!")});
        REQUIRE(reg.response.status == 200U);

        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = login_token(login.response.body);

        WHEN("GET /_matrix/client/v3/capabilities is requested with a valid token")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/capabilities", token, {}});

            THEN("the response is 200 with a capabilities object")
            {
                REQUIRE(response.response.status == 200U);
                REQUIRE(response.response.body.find("capabilities") != std::string::npos);
            }
        }

        WHEN("GET /_matrix/client/v3/capabilities is requested without a token")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/capabilities", {}, {}});

            THEN("the response is 401")
            {
                REQUIRE(response.response.status == 401U);
            }
        }
    }
}

SCENARIO("Push rules endpoint returns an empty global ruleset for authenticated clients",
         "[homeserver][client-server][pushrules]")
{
    GIVEN("a started runtime with a registered and logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const reg = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST",
                      "/_matrix/client/v3/register",
                      {},
                      merovingian::tests::registration_json("alice", "CorrectHorse7!")});
        REQUIRE(reg.response.status == 200U);

        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = login_token(login.response.body);

        WHEN("GET /_matrix/client/v3/pushrules/ is requested with a valid token")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/pushrules/", token, {}});

            THEN("the response is 200 with a global ruleset")
            {
                REQUIRE(response.response.status == 200U);
                REQUIRE(response.response.body.find("global") != std::string::npos);
            }
        }

        WHEN("GET /_matrix/client/v3/pushrules/ is requested without a token")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/pushrules/", {}, {}});

            THEN("the response is 401")
            {
                REQUIRE(response.response.status == 401U);
            }
        }
    }
}

SCENARIO("Keys upload accepts bodies larger than 4 KiB", "[homeserver][client-server][key-api]")
{
    GIVEN("a started runtime with a registered and logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const reg = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST",
                      "/_matrix/client/v3/register",
                      {},
                      merovingian::tests::registration_json("alice", "CorrectHorse7!")});
        REQUIRE(reg.response.status == 200U);

        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = login_token(login.response.body);

        WHEN("POST /keys/upload is called with a body larger than 4 KiB but within 64 KiB")
        {
            // Simulate a real Cinny OTK bundle: device keys + many one-time keys.
            // The body must exceed 4096 bytes to prove the old limit is gone.
            auto large_body = std::string{
                R"({"device_keys":{"@alice:example.org":{"DEVICE1":{"algorithms":[],"device_id":"DEVICE1","keys":{},"signatures":{},"user_id":"@alice:example.org"}}},"one_time_keys":{)"};
            for (int i = 0; i < 40; ++i)
            {
                if (i != 0)
                {
                    large_body += ',';
                }
                large_body += "\"signed_curve25519:KEY" + std::to_string(i) + "\":\"" + std::string(80U, 'a') + "\"";
            }
            large_body += "}}";
            REQUIRE(large_body.size() > 4096U);

            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/keys/upload", token, large_body});

            THEN("the response is 200, not 413")
            {
                REQUIRE(response.response.status == 200U);
            }
        }
    }
}

SCENARIO("OIDC discovery endpoints return 404 without authentication", "[homeserver][client-server]")
{
    GIVEN("a started runtime")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("GET /_matrix/client/unstable/org.matrix.msc2965/auth_metadata is called without a token")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/unstable/org.matrix.msc2965/auth_metadata", {}, {}});

            THEN("the response is 404, not 401")
            {
                // We do not implement OIDC; the endpoint must be absent (404) rather
                // than access-denied (401) so clients can probe and fall back gracefully.
                REQUIRE(response.response.status == 404U);
            }
        }

        WHEN("GET /_matrix/client/unstable/org.matrix.msc2965/auth_issuer is called without a token")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/unstable/org.matrix.msc2965/auth_issuer", {}, {}});

            THEN("the response is 404, not 401")
            {
                REQUIRE(response.response.status == 404U);
            }
        }
    }
}

SCENARIO("VoIP turn server endpoint returns an empty object for authenticated clients", "[homeserver][client-server]")
{
    GIVEN("a started runtime with a registered and logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const reg = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST",
                      "/_matrix/client/v3/register",
                      {},
                      merovingian::tests::registration_json("alice", "CorrectHorse7!")});
        REQUIRE(reg.response.status == 200U);

        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = login_token(login.response.body);

        WHEN("GET /_matrix/client/v3/voip/turnServer is called with a valid token")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/voip/turnServer", token, {}});

            THEN("the response is 200 with an empty object, not 404")
            {
                REQUIRE(response.response.status == 200U);
                REQUIRE(response.response.body == "{}");
            }
        }
    }
}

SCENARIO("Profile endpoint returns a user profile stub for authenticated clients", "[homeserver][client-server]")
{
    GIVEN("a started runtime with a registered and logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const reg = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST",
                      "/_matrix/client/v3/register",
                      {},
                      merovingian::tests::registration_json("alice", "CorrectHorse7!")});
        REQUIRE(reg.response.status == 200U);

        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = login_token(login.response.body);

        WHEN("GET /profile/{userId} is called with a percent-encoded user id")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/profile/%40alice%3Aexample.org", token, {}});

            THEN("the response is 200 and contains displayname and avatar_url fields")
            {
                REQUIRE(response.response.status == 200U);
                REQUIRE(response.response.body.find("displayname") != std::string::npos);
                REQUIRE(response.response.body.find("avatar_url") != std::string::npos);
            }
        }

        WHEN("GET /profile/{userId} is called without an access token")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/profile/%40alice%3Aexample.org", {}, {}});

            THEN("the response is 200 — profile lookup is unauthenticated per the Matrix spec")
            {
                REQUIRE(response.response.status == 200U);
                REQUIRE(response.response.body.find("displayname") != std::string::npos);
            }
        }
    }
}

SCENARIO("Media config endpoint returns upload size limit for authenticated clients", "[homeserver][client-server]")
{
    GIVEN("a started runtime with a registered and logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const reg = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST",
                      "/_matrix/client/v3/register",
                      {},
                      merovingian::tests::registration_json("alice", "CorrectHorse7!")});
        REQUIRE(reg.response.status == 200U);

        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = login_token(login.response.body);

        WHEN("GET /_matrix/media/v3/config is called with a valid token")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/media/v3/config", token, {}});

            THEN("the response is 200 and contains m.upload.size")
            {
                REQUIRE(response.response.status == 200U);
                REQUIRE(response.response.body.find("m.upload.size") != std::string::npos);
            }
        }

        WHEN("GET /_matrix/media/v3/config is called without an access token")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/media/v3/config", {}, {}});

            THEN("the response is 401")
            {
                REQUIRE(response.response.status == 401U);
            }
        }
    }
}

SCENARIO("User filter API stores and retrieves sync filters", "[homeserver][client-server][filter]")
{
    GIVEN("a started runtime with a registered and logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const reg = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST",
                      "/_matrix/client/v3/register",
                      {},
                      merovingian::tests::registration_json("alice", "CorrectHorse7!")});
        REQUIRE(reg.response.status == 200U);

        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = login_token(login.response.body);

        // @alice:example.org percent-encoded as it appears in a real browser URL
        auto constexpr user_filter_url = "/_matrix/client/v3/user/%40alice%3Aexample.org/filter";
        auto constexpr filter_body = R"({"room":{"timeline":{"limit":50}}})";

        WHEN("POST /user/{userId}/filter is called with a valid filter body")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", user_filter_url, token, filter_body});

            THEN("the response is 200 and contains a filter_id")
            {
                REQUIRE(response.response.status == 200U);
                REQUIRE(response.response.body.find("filter_id") != std::string::npos);
            }
        }

        WHEN("GET /user/{userId}/filter/{filterId} is called with a valid filter_id")
        {
            // Store a filter first so we have a filter_id to look up
            auto const store_resp = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", user_filter_url, token, filter_body});
            REQUIRE(store_resp.response.status == 200U);
            auto const fid = json_value(store_resp.response.body, "\"filter_id\":\"");

            auto const get_url = std::string{user_filter_url} + "/" + fid;
            auto const response =
                merovingian::homeserver::handle_client_server_request(runtime, {"GET", get_url, token, {}});

            THEN("the response is 200 and returns the stored filter body")
            {
                REQUIRE(response.response.status == 200U);
                REQUIRE(response.response.body.find("timeline") != std::string::npos);
            }
        }

        WHEN("GET /user/{userId}/filter/{filterId} is called with an unknown filter_id")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", std::string{user_filter_url} + "/nonexistent", token, {}});

            THEN("the response is 404")
            {
                REQUIRE(response.response.status == 404U);
            }
        }

        WHEN("POST /user/{userId}/filter is called without an access token")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", user_filter_url, {}, filter_body});

            THEN("the response is 401")
            {
                REQUIRE(response.response.status == 401U);
            }
        }
    }
}

SCENARIO("Join-by-id endpoint joins a room through the local join handler", "[homeserver][client-server]")
{
    GIVEN("a logged-in user who has created a room")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("alice", "CorrectHorse7!")})
                    .response.status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = login_token(login.response.body);

        auto const room = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v3/createRoom", token, {}});
        REQUIRE(room.response.status == 200U);
        auto const id = room_id(room.response.body);

        WHEN("POST /_matrix/client/v3/join/{roomId} is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/join/" + id, token, {}});

            THEN("the response is 200 and reports the joined room id")
            {
                REQUIRE(response.response.status == 200U);
                REQUIRE(response.response.body.find(id) != std::string::npos);
            }
        }

        WHEN("POST /_matrix/client/v3/join/{roomId} is called with a percent-encoded room ID")
        {
            auto const encoded_id = percent_encode_colons(id);
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/join/" + encoded_id, token, "{}"});

            THEN("the path segment is decoded before the local room lookup")
            {
                REQUIRE(response.response.status == 200U);
                REQUIRE(response.response.body.find(id) != std::string::npos);
                REQUIRE(response.response.body.find(encoded_id) == std::string::npos);
            }
        }

        WHEN("POST /_matrix/client/v3/join/{roomId} is called without an access token")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/join/" + id, {}, {}});

            THEN("the response is 401")
            {
                REQUIRE(response.response.status == 401U);
            }
        }
    }
}

SCENARIO("Account data endpoint stores and retrieves global account data", "[homeserver][client-server]")
{
    GIVEN("a logged-in client-server user")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("alice", "CorrectHorse7!")})
                    .response.status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = login_token(login.response.body);

        // @alice:example.org percent-encoded as a browser sends it
        auto constexpr account_data_url = "/_matrix/client/v3/user/%40alice%3Aexample.org/account_data/m.direct";
        auto constexpr direct_body = R"({"@bob:example.org":["!room1:example.org"]})";

        WHEN("PUT /account_data/{type} is called with a body")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"PUT", account_data_url, token, direct_body});

            THEN("the response is 200")
            {
                REQUIRE(response.response.status == 200U);
            }
        }

        WHEN("GET /account_data/{type} is called after a PUT")
        {
            auto const put = merovingian::homeserver::handle_client_server_request(
                runtime, {"PUT", account_data_url, token, direct_body});
            REQUIRE(put.response.status == 200U);

            auto const response =
                merovingian::homeserver::handle_client_server_request(runtime, {"GET", account_data_url, token, {}});

            THEN("the response is 200 and returns the stored content")
            {
                REQUIRE(response.response.status == 200U);
                REQUIRE(response.response.body.find("@bob:example.org") != std::string::npos);
            }
        }

        WHEN("GET /account_data/{type} is called for an unset type")
        {
            auto const response =
                merovingian::homeserver::handle_client_server_request(runtime, {"GET", account_data_url, token, {}});

            THEN("the response is 404")
            {
                REQUIRE(response.response.status == 404U);
            }
        }

        WHEN("PUT /account_data/{type} is called for another user")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"PUT", "/_matrix/client/v3/user/%40bob%3Aexample.org/account_data/m.direct", token, direct_body});

            THEN("the response is 403")
            {
                REQUIRE(response.response.status == 403U);
            }
        }

        WHEN("PUT /account_data/{type} is called without an access token")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"PUT", account_data_url, {}, direct_body});

            THEN("the response is 401")
            {
                REQUIRE(response.response.status == 401U);
            }
        }
    }
}
