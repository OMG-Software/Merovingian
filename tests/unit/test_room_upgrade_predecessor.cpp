// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// ADR-0239: when a room is upgraded to version 12 or later, the new create event's
// `predecessor` names the old room only. v1.19 lets the server choose ("When upgrading to
// room version 12 or later, the event_id property inside predecessor MAY be omitted", while
// the field "SHOULD still be populated where possible/practical"); a version 12 room is
// named by its create event, so this server omits it there and keeps it for older versions.
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
    REQUIRE(string_member(body, "access_token") != nullptr);
    return *string_member(body, "access_token");
}

} // namespace

SCENARIO("A room upgrade's predecessor names the last event only below room version 12",
         "[homeserver][rooms][room-upgrade][room-v12]")
{
    GIVEN("a version 11 room with a message")
    {
        auto started = merovingian::homeserver::start_client_server(upgrade_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = register_and_login(rt, "alice");
        auto const created = call(rt, "POST", "/_matrix/client/v3/createRoom", token, R"({"room_version":"11"})");
        REQUIRE(created.status == 200U);
        auto const room_id = *string_member(parse_object(created.body), "room_id");
        REQUIRE(call(rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/t1", token,
                     R"({"msgtype":"m.text","body":"hello"})")
                    .status == 200U);

        WHEN("it is upgraded")
        {
            auto const target = GENERATE(as<std::string>{}, "12", "11");
            auto const reply = call(rt, "POST", "/_matrix/client/v3/rooms/" + room_id + "/upgrade", token,
                                    R"({"new_version":")" + target + R"("})");
            REQUIRE(reply.status == 200U);
            auto const new_room = *string_member(parse_object(reply.body), "replacement_room");
            auto const create = parse_object(
                call(rt, "GET", "/_matrix/client/v3/rooms/" + new_room + "/state/m.room.create/", token).body);
            auto const* predecessor = object_member_as_object(create, "predecessor");

            THEN("predecessor names the old room, and the last event only when the target is below 12")
            {
                CAPTURE(target);
                REQUIRE(predecessor != nullptr);
                REQUIRE(string_member(*predecessor, "room_id") != nullptr);
                REQUIRE(*string_member(*predecessor, "room_id") == room_id);
                if (target == "12")
                {
                    REQUIRE(string_member(*predecessor, "event_id") == nullptr);
                }
                else
                {
                    REQUIRE(string_member(*predecessor, "event_id") != nullptr);
                }
            }
        }
    }
}
