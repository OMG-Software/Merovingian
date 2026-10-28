// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// ADR-0240: createRoom's power_level_content_override "is applied on top of the generated
// m.room.power_levels event content" key by key: an override key replaces that whole key of
// the generated content, nested maps included. The v12 m.room.tombstone level is part of the
// generated `events` map, so an override that supplies `events` decides it.
#include "../support/in_memory_database_config.hpp"
#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/client_server.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <cstdint>
#include <string>
#include <utility>

namespace
{

using namespace merovingian::tests;
using merovingian::homeserver::ClientServerRuntime;

[[nodiscard]] auto override_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
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

struct Reply final
{
    std::uint16_t status{0U};
    std::string body{};
};

[[nodiscard]] auto call(ClientServerRuntime& rt, std::string method, std::string target, std::string const& token,
                        std::string body = {}) -> Reply
{
    auto const result = merovingian::homeserver::handle_client_server_request(
        rt, {std::move(method), std::move(target), token, std::move(body)}, /*can_wait=*/false);
    return {static_cast<std::uint16_t>(result.response.status), result.response.body};
}

[[nodiscard]] auto register_and_login(ClientServerRuntime& rt) -> std::string
{
    REQUIRE(call(rt, "POST", "/_matrix/client/v3/register", {},
                 merovingian::tests::registration_json("alice", "CorrectHorse7!"))
                .status == 200U);
    auto const login =
        call(rt, "POST", "/_matrix/client/v3/login", {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},)"
             R"("password":"CorrectHorse7!","device_id":"ALICE_DEV"})");
    REQUIRE(login.status == 200U);
    auto const body = parse_object(login.body);
    return *string_member(body, "access_token");
}

[[nodiscard]] auto power_levels_of(ClientServerRuntime& rt, std::string const& token, std::string const& create_body)
    -> merovingian::canonicaljson::Object
{
    auto const created = call(rt, "POST", "/_matrix/client/v3/createRoom", token, create_body);
    REQUIRE(created.status == 200U);
    auto const created_body = parse_object(created.body);
    auto const room_id = *string_member(created_body, "room_id");
    auto const reply = call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/state/m.room.power_levels/", token);
    REQUIRE(reply.status == 200U);
    return parse_object(reply.body);
}

} // namespace

SCENARIO("A power_level_content_override key replaces the generated content's key",
         "[homeserver][rooms][create-room][power-level-override]")
{
    GIVEN("a logged-in user creating version 12 rooms")
    {
        auto started = merovingian::homeserver::start_client_server(override_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = register_and_login(rt);

        WHEN("the override supplies an events map without the tombstone")
        {
            auto const power_levels = power_levels_of(
                rt, token, R"({"room_version":"12","power_level_content_override":{"events":{"m.room.name":75}}})");

            THEN("the events map is the override's, tombstone and all")
            {
                auto const* events = object_member_as_object(power_levels, "events");
                REQUIRE(events != nullptr);
                REQUIRE(events->size() == 1U);
                REQUIRE(int_member(*events, "m.room.name") != nullptr);
                REQUIRE(*int_member(*events, "m.room.name") == 75);
                REQUIRE(int_member(*events, "m.room.tombstone") == nullptr);
            }
        }

        WHEN("the override supplies an empty events map")
        {
            auto const power_levels =
                power_levels_of(rt, token, R"({"room_version":"12","power_level_content_override":{"events":{}}})");

            THEN("no event type has its own level")
            {
                auto const* events = object_member_as_object(power_levels, "events");
                REQUIRE(events != nullptr);
                REQUIRE(events->empty());
            }
        }

        WHEN("the override leaves events alone")
        {
            auto const power_levels =
                power_levels_of(rt, token, R"({"room_version":"12","power_level_content_override":{"ban":60}})");

            THEN("the generated tombstone level stays, beside the overridden key")
            {
                auto const* events = object_member_as_object(power_levels, "events");
                REQUIRE(events != nullptr);
                REQUIRE(int_member(*events, "m.room.tombstone") != nullptr);
                REQUIRE(*int_member(*events, "m.room.tombstone") == 150);
                REQUIRE(*int_member(power_levels, "ban") == 60);
            }
        }
    }
}

// Spec: CS API v1.19, POST /createRoom, 400 M_INVALID_ROOM_STATE: "The initial state implied by
// the parameters to the createRoom request is invalid". An override key replaces the generated
// key whole (ADR-0240), so one of the wrong shape is refused before anything is created; it
// reached the auth rules only once the room and its first events were stored (review of #541).
SCENARIO("A power_level_content_override of the wrong shape is refused before anything is created",
         "[homeserver][rooms][create-room][power-level-override]")
{
    GIVEN("a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(override_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = register_and_login(rt);
        auto const override_json =
            GENERATE(as<std::string>{}, R"({"users":null})", R"({"users":{"@a:example.org":"x"}})", R"({"ban":"high"})",
                     R"({"events":[1]})");
        auto const version = GENERATE(as<std::string>{}, "10", "12");
        auto const rooms_before = rt.homeserver.database.persistent_store.rooms.size();

        WHEN("it creates a room with that override")
        {
            auto const created =
                call(rt, "POST", "/_matrix/client/v3/createRoom", token,
                     R"({"room_version":")" + version + R"(","power_level_content_override":)" + override_json + "}");

            THEN("the request is refused with 400 M_INVALID_ROOM_STATE and no room is stored")
            {
                CAPTURE(override_json, version, created.body);
                REQUIRE(created.status == 400U);
                REQUIRE(*string_member(parse_object(created.body), "errcode") == "M_INVALID_ROOM_STATE");
                REQUIRE(rt.homeserver.database.persistent_store.rooms.size() == rooms_before);
            }
        }
    }
}
