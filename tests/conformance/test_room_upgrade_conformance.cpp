// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/in_memory_database_config.hpp"

// Conformance tests for the server behaviour of POST /rooms/{roomId}/upgrade that the other upgrade tests
// do not cover: moving the old room's local aliases and lowering its power levels.
//
// Spec: Matrix Client-Server API v1.19, "Room Upgrades", "Server behaviour".
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#room-upgrades
//
// What is a MUST and what is not:
//   - "Moves any local aliases to the new room." is an unconditional step of the list: required.
//   - "Sends a m.room.tombstone event to the old room": required (covered elsewhere).
//   - "If possible, the power levels in the old room should also be modified ... setting events_default and
//     invite to the greater of 50 and users_default + 1": a SHOULD, and only where it is possible.

#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/client_server.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>

namespace
{

using namespace merovingian::tests;
using merovingian::homeserver::ClientServerRuntime;

[[nodiscard]] auto upgrade_config() -> merovingian::config::Config
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

[[nodiscard]] auto register_and_login(ClientServerRuntime& rt, std::string const& localpart) -> std::string
{
    REQUIRE(call(rt, "POST", "/_matrix/client/v3/register", {},
                 merovingian::tests::registration_json(localpart, "CorrectHorse7!"))
                .status == 200U);
    auto const login =
        call(rt, "POST", "/_matrix/client/v3/login", {},
             std::string{R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@)"} + localpart +
                 R"(:example.org"},"password":"CorrectHorse7!","device_id":")" + localpart + R"(_DEV"})");
    REQUIRE(login.status == 200U);
    auto const body = parse_object(login.body);
    auto const* token = string_member(body, "access_token");
    REQUIRE(token != nullptr);
    return *token;
}

[[nodiscard]] auto create_room(ClientServerRuntime& rt, std::string const& token, std::string const& body)
    -> std::string
{
    auto const reply = call(rt, "POST", "/_matrix/client/v3/createRoom", token, body);
    REQUIRE(reply.status == 200U);
    auto const parsed = parse_object(reply.body);
    auto const* room_id = string_member(parsed, "room_id");
    REQUIRE(room_id != nullptr);
    return *room_id;
}

auto invite_and_join(ClientServerRuntime& rt, std::string const& inviter, std::string const& room_id,
                     std::string const& localpart, std::string const& invitee) -> void
{
    REQUIRE(call(rt, "POST", "/_matrix/client/v3/rooms/" + room_id + "/invite", inviter,
                 R"({"user_id":"@)" + localpart + R"(:example.org"})")
                .status == 200U);
    REQUIRE(call(rt, "POST", "/_matrix/client/v3/rooms/" + room_id + "/join", invitee, "{}").status == 200U);
}

[[nodiscard]] auto upgrade(ClientServerRuntime& rt, std::string const& token, std::string const& room_id) -> Reply
{
    return call(rt, "POST", "/_matrix/client/v3/rooms/" + room_id + "/upgrade", token, R"({"new_version":"11"})");
}

[[nodiscard]] auto replacement_of(Reply const& reply) -> std::string
{
    REQUIRE(reply.status == 200U);
    auto const parsed = parse_object(reply.body);
    auto const* replacement = string_member(parsed, "replacement_room");
    REQUIRE(replacement != nullptr);
    return *replacement;
}

[[nodiscard]] auto alias_target(ClientServerRuntime& rt, std::string const& token, std::string const& alias)
    -> std::string
{
    auto const reply = call(rt, "GET", "/_matrix/client/v3/directory/room/" + alias, token);
    if (reply.status != 200U)
    {
        return {};
    }
    auto const parsed = parse_object(reply.body);
    auto const* room_id = string_member(parsed, "room_id");
    return room_id == nullptr ? std::string{} : *room_id;
}

[[nodiscard]] auto power_level(ClientServerRuntime& rt, std::string const& token, std::string const& room_id,
                               std::string_view key, std::int64_t fallback) -> std::int64_t
{
    auto const reply = call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/state/m.room.power_levels", token);
    REQUIRE(reply.status == 200U);
    auto const parsed = parse_object(reply.body);
    auto const* value = int_member(parsed, key);
    return value == nullptr ? fallback : *value;
}

} // namespace

// Spec: Room Upgrades, Server behaviour: "Moves any local aliases to the new room."
SCENARIO("Upgrading a room moves its local aliases to the replacement room", "[room-upgrade][conformance]")
{
    GIVEN("a room with an alias from createRoom and a second alias added through the directory")
    {
        auto started = merovingian::homeserver::start_client_server(upgrade_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_and_login(rt, "alice");
        auto const room_id = create_room(rt, alice, R"({"preset":"public_chat","room_alias_name":"lobby"})");
        REQUIRE(call(rt, "PUT", "/_matrix/client/v3/directory/room/%23annex:example.org", alice,
                     R"({"room_id":")" + room_id + R"("})")
                    .status == 200U);

        WHEN("alice upgrades the room")
        {
            auto const replacement = replacement_of(upgrade(rt, alice, room_id));

            THEN("both aliases resolve to the replacement room, not the tombstoned one")
            {
                REQUIRE(replacement != room_id);
                REQUIRE(alias_target(rt, alice, "%23lobby:example.org") == replacement);
                REQUIRE(alias_target(rt, alice, "%23annex:example.org") == replacement);
            }
        }
    }
}

// Spec: Room Upgrades, Server behaviour: "If possible, the power levels in the old room should also be
// modified to prevent sending of events and inviting new users. For example, setting events_default and
// invite to the greater of 50 and users_default + 1."
SCENARIO("Upgrading a room stops its members sending and inviting in the old room", "[room-upgrade][conformance]")
{
    GIVEN("a room where bob is an ordinary member")
    {
        auto started = merovingian::homeserver::start_client_server(upgrade_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_and_login(rt, "alice");
        auto const bob = register_and_login(rt, "bob");
        auto const room_id = create_room(rt, alice, R"({"preset":"public_chat"})");
        invite_and_join(rt, alice, room_id, "bob", bob);
        auto const message_path = [&room_id](std::string const& txn) {
            return "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/" + txn;
        };
        REQUIRE(call(rt, "PUT", message_path("before"), bob, R"({"msgtype":"m.text","body":"hi"})").status == 200U);

        WHEN("alice upgrades the room")
        {
            std::ignore = replacement_of(upgrade(rt, alice, room_id));

            THEN("events_default and invite are 50, and bob can neither send nor invite")
            {
                REQUIRE(power_level(rt, alice, room_id, "events_default", 0) == 50);
                REQUIRE(power_level(rt, alice, room_id, "invite", 0) == 50);
                REQUIRE(call(rt, "PUT", message_path("after"), bob, R"({"msgtype":"m.text","body":"hi"})").status ==
                        403U);
            }
        }
    }

    GIVEN("a room whose users_default is 60")
    {
        auto started = merovingian::homeserver::start_client_server(upgrade_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_and_login(rt, "alice");
        auto const room_id =
            create_room(rt, alice, R"({"preset":"public_chat","power_level_content_override":{"users_default":60}})");

        WHEN("alice upgrades the room")
        {
            std::ignore = replacement_of(upgrade(rt, alice, room_id));

            THEN("events_default and invite are users_default + 1, the greater of that and 50")
            {
                REQUIRE(power_level(rt, alice, room_id, "events_default", 0) == 61);
                REQUIRE(power_level(rt, alice, room_id, "invite", 0) == 61);
            }
        }
    }
}

// Spec: "If possible": an upgrader who may send the tombstone but may not change the power levels still
// upgrades the room; the old room's power levels are left as they were.
SCENARIO("An upgrade by a user who cannot change the old room's power levels still succeeds",
         "[room-upgrade][conformance]")
{
    GIVEN("a room where only the creator may send power levels and bob, a moderator, may send the tombstone")
    {
        auto started = merovingian::homeserver::start_client_server(upgrade_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_and_login(rt, "alice");
        auto const bob = register_and_login(rt, "bob");
        auto const room_id =
            create_room(rt, alice,
                        R"({"preset":"public_chat","power_level_content_override":{"users":{"@bob:example.org":50},)"
                        R"("events":{"m.room.power_levels":100,"m.room.tombstone":50}}})");
        invite_and_join(rt, alice, room_id, "bob", bob);

        WHEN("bob upgrades the room")
        {
            auto const reply = upgrade(rt, bob, room_id);

            THEN("the upgrade is answered 200 and the old room's events_default is unchanged")
            {
                REQUIRE(reply.status == 200U);
                REQUIRE(power_level(rt, alice, room_id, "events_default", 0) == 0);
            }
        }
    }
}
