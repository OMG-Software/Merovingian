// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/InMemoryDatabaseConfig.hpp"
#include "../support/JsonTestSupport.hpp"
#include "../support/MasterKey.hpp"
#include "../support/RegistrationToken.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

// GET /relations?recurse=true walks at most 3 levels and offers at most 2048 events beyond the first level
// (ADR-0475). The spec asks for at least 3 levels and sets no maximum, so these bounds are this server's.

namespace
{

using namespace merovingian::tests;
using merovingian::homeserver::ClientServerRuntime;

[[nodiscard]] auto relations_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    // The wide-graph scenario sends over 2000 events from one address; the default per-IP limit would refuse them.
    auto rate_limits = merovingian::config::ClientRateLimitsConfig{};
    rate_limits.default_per_ip = {100000U, 60U};
    return merovingian::config::Config{
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::tests::in_memory_database_config(),
        security,
        rate_limits,
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

[[nodiscard]] auto event_id_of(Reply const& reply) -> std::string
{
    REQUIRE(reply.status == 200U);
    auto const parsed = parse_object(reply.body);
    auto const* id = string_member(parsed, "event_id");
    REQUIRE(id != nullptr);
    return *id;
}

[[nodiscard]] auto send_related(ClientServerRuntime& rt, std::string const& token, std::string const& room_id,
                                std::string const& target, std::size_t counter) -> std::string
{
    return event_id_of(call(
        rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/t" + std::to_string(counter), token,
        R"({"msgtype":"m.text","body":"r","m.relates_to":{"rel_type":"m.reference","event_id":")" + target + R"("}})"));
}

[[nodiscard]] auto chunk_ids(Reply const& reply) -> std::vector<std::string>
{
    auto ids = std::vector<std::string>{};
    auto const parsed = parse_object(reply.body);
    auto const* chunk = object_member_as_array(parsed, "chunk");
    REQUIRE(chunk != nullptr);
    for (auto const& value : *chunk)
    {
        auto const* event = std::get_if<merovingian::canonicaljson::Object>(&value.storage());
        REQUIRE(event != nullptr);
        ids.push_back(*string_member(*event, "event_id"));
    }
    return ids;
}

} // namespace

SCENARIO("A recursive relations walk is bounded in depth and in the events it examines",
         "[relations][recurse][security]")
{
    GIVEN("a root with a chain of relations four levels deep")
    {
        auto started = merovingian::homeserver::start_client_server(relations_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        REQUIRE(call(rt, "POST", "/_matrix/client/v3/register", {},
                     merovingian::tests::registration_json("alice", "CorrectHorse7!"))
                    .status == 200U);
        auto const login = parse_object(
            call(
                rt, "POST", "/_matrix/client/v3/login", {},
                R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"D"})")
                .body);
        auto const token = *string_member(login, "access_token");
        auto const room_id = *string_member(
            parse_object(call(rt, "POST", "/_matrix/client/v3/createRoom", token, R"({"preset":"public_chat"})").body),
            "room_id");
        auto const root =
            event_id_of(call(rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/root", token,
                             R"({"msgtype":"m.text","body":"root"})"));
        auto counter = std::size_t{0U};
        auto const level1 = send_related(rt, token, room_id, root, ++counter);
        auto const level2 = send_related(rt, token, room_id, level1, ++counter);
        auto const level3 = send_related(rt, token, room_id, level2, ++counter);
        auto const level4 = send_related(rt, token, room_id, level3, ++counter);
        auto const path = "/_matrix/client/v1/rooms/" + room_id + "/relations/" + root + "?recurse=true";

        WHEN("the relations are fetched with recurse=true")
        {
            auto const reply = call(rt, "GET", path, token);

            THEN("three levels are returned, the fourth is not, and recursion_depth is 3")
            {
                REQUIRE(reply.status == 200U);
                auto const ids = chunk_ids(reply);
                REQUIRE(ids.size() == 3U);
                REQUIRE(std::ranges::count(ids, level4) == 0);
                auto const parsed = parse_object(reply.body);
                REQUIRE(*int_member(parsed, "recursion_depth") == 3);
            }
        }

        WHEN("a second event relates to the first level")
        {
            // An event ID is a hash of the event, so a loop cannot be formed; each event is listed once.
            std::ignore = send_related(rt, token, room_id, level1, ++counter);
            auto const ids = chunk_ids(call(rt, "GET", path, token));

            THEN("no event is listed twice")
            {
                auto sorted = ids;
                std::ranges::sort(sorted);
                REQUIRE(std::ranges::adjacent_find(sorted) == sorted.end());
            }
        }
    }
}

SCENARIO("A recursive relations walk stops once it has examined its cap of events beyond the first level",
         "[relations][recurse][security]")
{
    GIVEN("a direct child with more children than the walk may examine, and a grandchild below the first of them")
    {
        auto started = merovingian::homeserver::start_client_server(relations_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        REQUIRE(call(rt, "POST", "/_matrix/client/v3/register", {},
                     merovingian::tests::registration_json("alice", "CorrectHorse7!"))
                    .status == 200U);
        auto const login = parse_object(
            call(
                rt, "POST", "/_matrix/client/v3/login", {},
                R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"D"})")
                .body);
        auto const token = *string_member(login, "access_token");
        auto const room_id = *string_member(
            parse_object(call(rt, "POST", "/_matrix/client/v3/createRoom", token, R"({"preset":"public_chat"})").body),
            "room_id");
        auto const root =
            event_id_of(call(rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/root", token,
                             R"({"msgtype":"m.text","body":"root"})"));
        auto counter = std::size_t{0U};
        auto const level1 = send_related(rt, token, room_id, root, ++counter);
        // The cap is 2048 events beyond the first level; this is past it.
        auto const second_level_count = std::size_t{2048U} + 10U;
        auto second_level = std::vector<std::string>{};
        for (auto index = std::size_t{0U}; index < second_level_count; ++index)
        {
            second_level.push_back(send_related(rt, token, room_id, level1, ++counter));
        }
        auto const level3 = send_related(rt, token, room_id, second_level.front(), ++counter);

        WHEN("the relations are fetched with recurse=true")
        {
            auto const reply = call(
                rt, "GET", "/_matrix/client/v1/rooms/" + room_id + "/relations/" + root + "?recurse=true&limit=1000000",
                token);

            THEN("the walk stops in the second level: depth is below 3 and the third level is not listed")
            {
                REQUIRE(reply.status == 200U);
                auto const parsed = parse_object(reply.body);
                REQUIRE(*int_member(parsed, "recursion_depth") < 3);
                auto const ids = chunk_ids(reply);
                REQUIRE(std::ranges::count(ids, level3) == 0);
                REQUIRE(ids.size() <= 1000000U);
            }
        }
    }
}
