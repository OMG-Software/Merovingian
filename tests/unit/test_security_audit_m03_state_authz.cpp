// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/in_memory_database_config.hpp"
//
// +-------------------------------------------------------------------------+
// |     SECURITY AUDIT M-03: ROOM STATE READ AUTHORIZATION                  |
// |                                                                         |
// |  Spec: Matrix Client-Server API v1.19                                   |
// |  URL:  ../../docs/matrix-v1.19-spec/client-server-api.md                 |
// |        #get_matrixclientv3roomsroomidstateeventtypestatekey             |
// |                                                                         |
// |  Bug: GET /rooms/{roomId}/state/{eventType}/{stateKey} checked only     |
// |  that the room existed, not that the caller was ever a member of it -   |
// |  any authenticated user could read any room's state, including         |
// |  private/invite-only rooms. The spec requires: joined members see       |
// |  current state, users who left see state as of their leave point, and  |
// |  everyone else (including a request for a room that does not exist)    |
// |  gets an indistinguishable 403.                                        |
// +-------------------------------------------------------------------------+

#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/client_server.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

namespace
{

[[nodiscard]] auto m03_registration_enabled_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    // A runtime refuses to mint a signing secret it cannot encrypt at rest
    // (0.12.5 audit, finding 1), so every fixture needs a master key.
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::tests::in_memory_database_config(),
        security,
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto m03_login_token(std::string const& body) -> std::string
{
    auto const key = std::string{"\"access_token\":\""};
    auto const begin = body.find(key);
    REQUIRE(begin != std::string::npos);
    auto const value_begin = begin + key.size();
    auto const value_end = body.find('"', value_begin);
    REQUIRE(value_end != std::string::npos);
    return body.substr(value_begin, value_end - value_begin);
}

[[nodiscard]] auto m03_room_id(std::string const& body) -> std::string
{
    auto const key = std::string{"\"room_id\":\""};
    auto const begin = body.find(key);
    REQUIRE(begin != std::string::npos);
    auto const value_begin = begin + key.size();
    auto const value_end = body.find('"', value_begin);
    REQUIRE(value_end != std::string::npos);
    return body.substr(value_begin, value_end - value_begin);
}

[[nodiscard]] auto m03_register_and_login(merovingian::homeserver::ClientServerRuntime& runtime,
                                          std::string_view localpart, std::string_view device_id) -> std::string
{
    auto const register_response = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST",
                  "/_matrix/client/v3/register",
                  {},
                  merovingian::tests::registration_json(localpart, "CorrectHorse7!")});
    REQUIRE(register_response.response.status == 200U);

    auto const login_response = merovingian::homeserver::handle_client_server_request(
        runtime,
        {"POST",
         "/_matrix/client/v3/login",
         {},
         R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@)" + std::string{localpart} +
             R"(:example.org"},"password":"CorrectHorse7!","device_id":")" + std::string{device_id} + R"("})"});
    REQUIRE(login_response.response.status == 200U);
    return m03_login_token(login_response.response.body);
}

auto constexpr custom_state_type = std::string_view{"com.example.custom_state"};

} // namespace

SCENARIO("A joined room member reads the current value of a room's state via GET state",
         "[security][client-server][m03]")
{
    GIVEN("a room with a custom state event set by its joined creator")
    {
        auto started = merovingian::homeserver::start_client_server(m03_registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const alice_token = m03_register_and_login(runtime, "alice", "ALICE_DEV");
        auto const bob_token = m03_register_and_login(runtime, "bob", "BOB_DEV");

        auto const create = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v3/createRoom", alice_token, R"({"preset":"public_chat"})"});
        REQUIRE(create.response.status == 200U);
        auto const room = m03_room_id(create.response.body);

        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST", "/_matrix/client/v3/join/" + room, bob_token, "{}"})
                    .response.status == 200U);

        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"PUT", "/_matrix/client/v3/rooms/" + room + "/state/" + std::string{custom_state_type},
                              alice_token, R"({"value":"current"})"})
                    .response.status == 200U);

        WHEN("the joined member requests the state event")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET",
                          "/_matrix/client/v3/rooms/" + room + "/state/" + std::string{custom_state_type},
                          bob_token,
                          {}});

            THEN("the current state content is returned")
            {
                REQUIRE(response.response.status == 200U);
                REQUIRE(response.response.body.find("current") != std::string::npos);
            }
        }
    }
}

SCENARIO("A user with no membership row cannot read a room's state", "[security][client-server][m03]")
{
    GIVEN("a room with a custom state event, and a registered user who never joined it")
    {
        auto started = merovingian::homeserver::start_client_server(m03_registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const alice_token = m03_register_and_login(runtime, "alice", "ALICE_DEV");
        auto const mallory_token = m03_register_and_login(runtime, "mallory", "MALLORY_DEV");

        auto const create = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v3/createRoom", alice_token, R"({"preset":"public_chat"})"});
        REQUIRE(create.response.status == 200U);
        auto const room = m03_room_id(create.response.body);

        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"PUT", "/_matrix/client/v3/rooms/" + room + "/state/" + std::string{custom_state_type},
                              alice_token, R"({"value":"secret-payload"})"})
                    .response.status == 200U);

        WHEN("mallory, who has no membership row in this room, requests its state")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET",
                          "/_matrix/client/v3/rooms/" + room + "/state/" + std::string{custom_state_type},
                          mallory_token,
                          {}});

            THEN("the request is refused with 403 M_FORBIDDEN and the state content never appears in the body")
            {
                REQUIRE(response.response.status == 403U);
                REQUIRE(response.response.body.find("M_FORBIDDEN") != std::string::npos);
                REQUIRE(response.response.body.find("secret-payload") == std::string::npos);
            }
        }
    }
}

SCENARIO("A non-member gets an indistinguishable 403 for a real room and a room that does not exist",
         "[security][client-server][m03]")
{
    GIVEN("a registered user who is not a member of an existing room, and a room id that does not exist at all")
    {
        auto started = merovingian::homeserver::start_client_server(m03_registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const alice_token = m03_register_and_login(runtime, "alice", "ALICE_DEV");
        auto const mallory_token = m03_register_and_login(runtime, "mallory", "MALLORY_DEV");

        // A private room mallory is never invited to or a member of.
        auto const create = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v3/createRoom", alice_token, R"({"name":"Private room"})"});
        REQUIRE(create.response.status == 200U);
        auto const real_room = m03_room_id(create.response.body);

        WHEN("mallory requests state for the real room she is not in, and for a room id that was never created")
        {
            auto const for_real_room = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET",
                          "/_matrix/client/v3/rooms/" + real_room + "/state/" + std::string{custom_state_type},
                          mallory_token,
                          {}});
            auto const for_missing_room = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"GET",
                 "/_matrix/client/v3/rooms/!does-not-exist:example.org/state/" + std::string{custom_state_type},
                 mallory_token,
                 {}});

            THEN("both responses are the identical 403, so room existence cannot be inferred")
            {
                REQUIRE(for_real_room.response.status == 403U);
                REQUIRE(for_missing_room.response.status == 403U);
                REQUIRE(for_real_room.response.status == for_missing_room.response.status);
                REQUIRE(for_real_room.response.body == for_missing_room.response.body);
            }
        }
    }
}

SCENARIO("A user who left a room sees the state as of their leave point, not a value written afterwards",
         "[security][client-server][m03]")
{
    GIVEN("a room where a state event is set, a member leaves, and the state is changed again afterwards")
    {
        auto started = merovingian::homeserver::start_client_server(m03_registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const alice_token = m03_register_and_login(runtime, "alice", "ALICE_DEV");
        auto const bob_token = m03_register_and_login(runtime, "bob", "BOB_DEV");

        auto const create = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v3/createRoom", alice_token, R"({"preset":"public_chat"})"});
        REQUIRE(create.response.status == 200U);
        auto const room = m03_room_id(create.response.body);

        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST", "/_matrix/client/v3/join/" + room, bob_token, "{}"})
                    .response.status == 200U);

        // Version 1 of the state, set while bob is still joined.
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"PUT", "/_matrix/client/v3/rooms/" + room + "/state/" + std::string{custom_state_type},
                              alice_token, R"({"value":"before-leave"})"})
                    .response.status == 200U);

        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST", "/_matrix/client/v3/rooms/" + room + "/leave", bob_token, "{}"})
                    .response.status == 200U);

        // Version 2 of the same state event, written after bob left - bob
        // must never see this value.
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"PUT", "/_matrix/client/v3/rooms/" + room + "/state/" + std::string{custom_state_type},
                              alice_token, R"({"value":"after-leave"})"})
                    .response.status == 200U);

        WHEN("bob, who has left, requests the state event")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET",
                          "/_matrix/client/v3/rooms/" + room + "/state/" + std::string{custom_state_type},
                          bob_token,
                          {}});

            THEN("the value in force at his leave point is returned, not the later value")
            {
                REQUIRE(response.response.status == 200U);
                REQUIRE(response.response.body.find("before-leave") != std::string::npos);
                REQUIRE(response.response.body.find("after-leave") == std::string::npos);
            }
        }
    }
}

// Spec (client-server-api.md, GET /rooms/{roomId}/state/{eventType}/{stateKey}): "If the user
// is joined to the room then the state is taken from the current state of the room. If the user
// has left the room then the state is taken from the state of the room when they left", and the
// only 403 is "You aren't a member of the room and weren't previously a member of the room". A
// banned user WAS a member, so the 403 does not apply; they read the state as it was when they
// were ejected, never anything written after (CSAZ-2). This scenario used to assert that a ban
// denies access outright, which read "has left" more narrowly than the 403 sentence allows and
// disagreed with `GET /members` and `initialSync`, which serve a banned user the room as it
// was at the ban.
SCENARIO("A banned user reads a room's state only as it was when they were banned",
         "[security][client-server][m03][csaz-2]")
{
    GIVEN("a room from which a member has been banned, with state written before the ban")
    {
        auto started = merovingian::homeserver::start_client_server(m03_registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const alice_token = m03_register_and_login(runtime, "alice", "ALICE_DEV");
        auto const bob_token = m03_register_and_login(runtime, "bob", "BOB_DEV");

        auto const create = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v3/createRoom", alice_token, R"({"preset":"public_chat"})"});
        REQUIRE(create.response.status == 200U);
        auto const room = m03_room_id(create.response.body);

        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST", "/_matrix/client/v3/join/" + room, bob_token, "{}"})
                    .response.status == 200U);

        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"PUT", "/_matrix/client/v3/rooms/" + room + "/state/" + std::string{custom_state_type},
                              alice_token, R"({"value":"before-ban"})"})
                    .response.status == 200U);

        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST", "/_matrix/client/v3/rooms/" + room + "/ban", alice_token,
                              R"({"user_id":"@bob:example.org"})"})
                    .response.status == 200U);

        // Version 2 of the same state event, written after the ban: the banned user must
        // never see this value.
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"PUT", "/_matrix/client/v3/rooms/" + room + "/state/" + std::string{custom_state_type},
                              alice_token, R"({"value":"after-ban"})"})
                    .response.status == 200U);

        WHEN("the banned user requests the state event")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET",
                          "/_matrix/client/v3/rooms/" + room + "/state/" + std::string{custom_state_type},
                          bob_token,
                          {}});

            THEN("the value in force when he was banned is returned, not the later one")
            {
                REQUIRE(response.response.status == 200U);
                REQUIRE(response.response.body.find("before-ban") != std::string::npos);
                REQUIRE(response.response.body.find("after-ban") == std::string::npos);
            }
        }
    }
}
