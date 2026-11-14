// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/InMemoryDatabaseConfig.hpp"
#include "../support/TempDirectory.hpp"

// Security audit run-4 F-03 (ADR-0581): a room alias is created only while its creator is under
// max_room_aliases_per_user and its room under max_room_aliases_per_room, so the alias listing
// cannot be made to hold the runtime lock for as long as one account likes.
//
// Spec: Matrix Client-Server API v1.19, PUT /directory/room/{roomAlias}, POST /createRoom,
// GET /rooms/{roomId}/aliases. The spec sets no limit; M_TOO_LARGE is this server's per-user cap code.
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md

#include "../support/JsonTestSupport.hpp"
#include "../support/MasterKey.hpp"
#include "../support/RegistrationToken.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/core/QueryParams.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <utility>

namespace
{

using namespace merovingian::tests;
using merovingian::homeserver::ClientServerRuntime;

constexpr auto as_token = "alias-bridge-as-token-secret";

struct Reply final
{
    std::uint16_t status{0U};
    std::string body{};
};

[[nodiscard]] auto caps_config(std::uint32_t per_user, std::uint32_t per_room,
                               std::string const& registration_path = {}) -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    auto server = merovingian::config::ServerConfig{};
    server.client_api.max_room_aliases_per_user = per_user;
    server.client_api.max_room_aliases_per_room = per_room;
    auto config = merovingian::config::Config{
        server,   merovingian::config::ListenersConfig{},        merovingian::tests::in_memory_database_config(),
        security, merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
    };
    if (!registration_path.empty())
    {
        config.appservice().registration_files = {registration_path};
    }
    return config;
}

[[nodiscard]] auto write_bridge_registration(std::filesystem::path const& path) -> std::string
{
    auto out = std::ofstream{path, std::ios::binary};
    out << R"({
        "id": "alias-bridge",
        "url": "http://127.0.0.1:1234",
        "as_token": "alias-bridge-as-token-secret",
        "hs_token": "alias-bridge-hs-token-secret",
        "sender_localpart": "_alias_bot",
        "namespaces": {
            "users": [{"exclusive": true, "regex": "@_alias_bridge_.*"}],
            "aliases": [{"exclusive": true, "regex": "#_alias_bridge_.*"}],
            "rooms": []
        }
    })";
    out.close();
    REQUIRE(out.good());
    return path.string();
}

[[nodiscard]] auto call(ClientServerRuntime& rt, std::string method, std::string target, std::string const& token,
                        std::string body = {}) -> Reply
{
    auto const result = merovingian::homeserver::handle_client_server_request(
        rt, {std::move(method), std::move(target), token, std::move(body)}, /*can_wait=*/false);
    return {static_cast<std::uint16_t>(result.response.status), result.response.body};
}

[[nodiscard]] auto errcode_of(Reply const& reply) -> std::string
{
    auto const body = parse_object(reply.body);
    auto const* errcode = string_member(body, "errcode");
    return errcode == nullptr ? std::string{} : *errcode;
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

[[nodiscard]] auto create_room(ClientServerRuntime& rt, std::string const& token,
                               std::string const& body = R"({"preset":"public_chat"})") -> std::string
{
    auto const reply = call(rt, "POST", "/_matrix/client/v3/createRoom", token, body);
    REQUIRE(reply.status == 200U);
    auto const parsed = parse_object(reply.body);
    auto const* room_id = string_member(parsed, "room_id");
    REQUIRE(room_id != nullptr);
    return *room_id;
}

[[nodiscard]] auto alias_name(std::string const& stem, std::size_t index) -> std::string
{
    return "#" + stem + std::to_string(index) + ":example.org";
}

[[nodiscard]] auto alias_path(std::string const& alias) -> std::string
{
    return "/_matrix/client/v3/directory/room/" + merovingian::core::percent_encode_path_component(alias);
}

[[nodiscard]] auto put_alias(ClientServerRuntime& rt, std::string const& token, std::string const& alias,
                             std::string const& room_id) -> Reply
{
    return call(rt, "PUT", alias_path(alias), token, R"({"room_id":")" + room_id + R"("})");
}

[[nodiscard]] auto stored_aliases(ClientServerRuntime& rt) -> std::size_t
{
    return rt.homeserver.database.persistent_store.room_aliases.size();
}

[[nodiscard]] auto alias_stored(ClientServerRuntime& rt, std::string const& alias) -> bool
{
    return merovingian::database::find_room_alias(rt.homeserver.database.persistent_store, alias).has_value();
}

} // namespace

SCENARIO("A user cannot create more room aliases than max_room_aliases_per_user",
         "[f03][directory][alias][room-alias-caps]")
{
    GIVEN("a server that allows three aliases per user and alice with two rooms")
    {
        auto started = merovingian::homeserver::start_client_server(caps_config(3U, 100U));
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_and_login(rt, "alice");
        auto const bob = register_and_login(rt, "bob");
        auto const room = create_room(rt, alice);
        auto const other_room = create_room(rt, alice);
        for (auto index = std::size_t{0U}; index < 3U; ++index)
        {
            REQUIRE(put_alias(rt, alice, alias_name("held", index), room).status == 200U);
        }

        WHEN("alice creates a fourth alias")
        {
            auto const reply = put_alias(rt, alice, alias_name("held", 3U), room);

            THEN("the answer is 400 M_TOO_LARGE and no row is written")
            {
                REQUIRE(reply.status == 400U);
                REQUIRE(errcode_of(reply) == "M_TOO_LARGE");
                REQUIRE(stored_aliases(rt) == 3U);
                REQUIRE_FALSE(alias_stored(rt, alias_name("held", 3U)));
            }
        }

        WHEN("alice repeats an alias she already holds, for the same room")
        {
            auto const reply = put_alias(rt, alice, alias_name("held", 1U), room);

            THEN("the old answer 200 is kept at the cap")
            {
                REQUIRE(reply.status == 200U);
                REQUIRE(stored_aliases(rt) == 3U);
            }
        }

        WHEN("alice names an alias she holds for another room")
        {
            auto const reply = put_alias(rt, alice, alias_name("held", 1U), other_room);

            THEN("the old answer 409 M_ROOM_IN_USE is kept at the cap")
            {
                REQUIRE(reply.status == 409U);
                REQUIRE(errcode_of(reply) == "M_ROOM_IN_USE");
            }
        }

        WHEN("bob, who holds no alias, creates one in his own room")
        {
            auto const bobs_room = create_room(rt, bob);
            auto const reply = put_alias(rt, bob, alias_name("bobs", 0U), bobs_room);

            THEN("alice's cap does not apply to him")
            {
                REQUIRE(reply.status == 200U);
            }
        }

        WHEN("alice deletes one alias and creates another")
        {
            auto const deleted = call(rt, "DELETE", alias_path(alias_name("held", 0U)), alice);
            auto const reply = put_alias(rt, alice, alias_name("held", 3U), room);

            THEN("the freed place is usable")
            {
                REQUIRE(deleted.status == 200U);
                REQUIRE(reply.status == 200U);
                REQUIRE(stored_aliases(rt) == 3U);
            }
        }
    }
}

SCENARIO("A room cannot hold more aliases than max_room_aliases_per_room", "[f03][directory][alias][room-alias-caps]")
{
    GIVEN("a server that allows two aliases per room and a room holding two")
    {
        auto started = merovingian::homeserver::start_client_server(caps_config(100U, 2U));
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_and_login(rt, "alice");
        auto const room = create_room(rt, alice);
        auto const other_room = create_room(rt, alice);
        REQUIRE(put_alias(rt, alice, alias_name("full", 0U), room).status == 200U);
        REQUIRE(put_alias(rt, alice, alias_name("full", 1U), room).status == 200U);

        WHEN("a third alias is created for that room")
        {
            auto const reply = put_alias(rt, alice, alias_name("full", 2U), room);

            THEN("the answer is 400 M_TOO_LARGE and no row is written")
            {
                REQUIRE(reply.status == 400U);
                REQUIRE(errcode_of(reply) == "M_TOO_LARGE");
                REQUIRE(stored_aliases(rt) == 2U);
            }
        }

        WHEN("an alias already held by the room is repeated")
        {
            auto const reply = put_alias(rt, alice, alias_name("full", 0U), room);

            THEN("the old answer 200 is kept at the cap")
            {
                REQUIRE(reply.status == 200U);
            }
        }

        WHEN("an alias is created for another room")
        {
            auto const reply = put_alias(rt, alice, alias_name("full", 2U), other_room);

            THEN("the first room's cap does not apply")
            {
                REQUIRE(reply.status == 200U);
            }
        }
    }
}

SCENARIO("createRoom with room_alias_name counts toward the per-user alias cap",
         "[f03][createroom][alias][room-alias-caps]")
{
    GIVEN("a server that allows one alias per user and alice holding one")
    {
        auto started = merovingian::homeserver::start_client_server(caps_config(1U, 100U));
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_and_login(rt, "alice");
        auto const room = create_room(rt, alice);
        REQUIRE(put_alias(rt, alice, alias_name("only", 0U), room).status == 200U);
        auto const rooms_before = rt.homeserver.database.rooms.size();

        WHEN("alice creates a room with a room_alias_name")
        {
            auto const reply =
                call(rt, "POST", "/_matrix/client/v3/createRoom", alice, R"({"room_alias_name":"second"})");

            THEN("the answer is 400 M_TOO_LARGE, no room is created and no alias is stored")
            {
                REQUIRE(reply.status == 400U);
                REQUIRE(errcode_of(reply) == "M_TOO_LARGE");
                REQUIRE(rt.homeserver.database.rooms.size() == rooms_before);
                REQUIRE(stored_aliases(rt) == 1U);
                REQUIRE_FALSE(alias_stored(rt, "#second:example.org"));
            }
        }

        WHEN("alice creates a room without a room_alias_name")
        {
            auto const reply = call(rt, "POST", "/_matrix/client/v3/createRoom", alice, R"({})");

            THEN("the room is created")
            {
                REQUIRE(reply.status == 200U);
            }
        }

        WHEN("bob, who holds no alias, creates a room with a room_alias_name")
        {
            auto const bob = register_and_login(rt, "bob");
            auto const reply = call(rt, "POST", "/_matrix/client/v3/createRoom", bob, R"({"room_alias_name":"bobs"})");

            THEN("the room and its alias are created")
            {
                REQUIRE(reply.status == 200U);
                REQUIRE(alias_stored(rt, "#bobs:example.org"));
            }
        }

        WHEN("alice asks for the alias name she already holds")
        {
            auto const reply =
                call(rt, "POST", "/_matrix/client/v3/createRoom", alice, R"({"room_alias_name":"only0"})");

            THEN("the old answer 400 M_ROOM_IN_USE is kept at the cap")
            {
                REQUIRE(reply.status == 400U);
                REQUIRE(errcode_of(reply) == "M_ROOM_IN_USE");
            }
        }
    }
}

SCENARIO("An application service is exempt from the per-user alias cap but not the per-room cap",
         "[f03][directory][alias][appservice][room-alias-caps]")
{
    GIVEN("a bridge and a server that allows one alias per user and three per room")
    {
        auto const path = merovingian::tests::unique_temporary_path("merovingian-f03-alias-bridge", ".json");
        auto const registration = write_bridge_registration(path);
        auto started = merovingian::homeserver::start_client_server(caps_config(1U, 3U, registration));
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const bridge_room = create_room(rt, as_token);
        auto const second_room = create_room(rt, as_token);

        WHEN("the bridge creates aliases past the per-user cap in two rooms")
        {
            auto const first = put_alias(rt, as_token, alias_name("_alias_bridge_a", 0U), bridge_room);
            auto const second = put_alias(rt, as_token, alias_name("_alias_bridge_a", 1U), bridge_room);
            auto const third = put_alias(rt, as_token, alias_name("_alias_bridge_b", 0U), second_room);

            THEN("every one is created")
            {
                REQUIRE(first.status == 200U);
                REQUIRE(second.status == 200U);
                REQUIRE(third.status == 200U);
                REQUIRE(stored_aliases(rt) == 3U);
            }
        }

        WHEN("the bridge fills one room to the per-room cap and asks for one more")
        {
            for (auto index = std::size_t{0U}; index < 3U; ++index)
            {
                REQUIRE(put_alias(rt, as_token, alias_name("_alias_bridge_c", index), bridge_room).status == 200U);
            }
            auto const reply = put_alias(rt, as_token, alias_name("_alias_bridge_c", 3U), bridge_room);

            THEN("the per-room cap still refuses it with 400 M_TOO_LARGE")
            {
                REQUIRE(reply.status == 400U);
                REQUIRE(errcode_of(reply) == "M_TOO_LARGE");
                REQUIRE(stored_aliases(rt) == 3U);
            }
        }

        std::filesystem::remove(path);
    }
}

SCENARIO("The aliases listing returns only the aliases of the room asked about",
         "[f03][directory][alias][room-alias-caps]")
{
    GIVEN("alice with two rooms that hold aliases")
    {
        auto started = merovingian::homeserver::start_client_server(caps_config(100U, 100U));
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_and_login(rt, "alice");
        auto const room = create_room(rt, alice);
        auto const other_room = create_room(rt, alice);
        REQUIRE(put_alias(rt, alice, alias_name("one", 0U), room).status == 200U);
        REQUIRE(put_alias(rt, alice, alias_name("one", 1U), room).status == 200U);
        REQUIRE(put_alias(rt, alice, alias_name("two", 0U), other_room).status == 200U);

        WHEN("alice lists the first room's aliases")
        {
            auto const reply =
                call(rt, "GET",
                     "/_matrix/client/v3/rooms/" + merovingian::core::percent_encode_path_component(room) + "/aliases",
                     alice);

            THEN("both of its aliases and no other are returned")
            {
                REQUIRE(reply.status == 200U);
                REQUIRE(reply.body.find("#one0:example.org") != std::string::npos);
                REQUIRE(reply.body.find("#one1:example.org") != std::string::npos);
                REQUIRE(reply.body.find("#two0:example.org") == std::string::npos);
            }
        }

        WHEN("alice lists the second room's aliases")
        {
            auto const reply = call(rt, "GET",
                                    "/_matrix/client/v3/rooms/" +
                                        merovingian::core::percent_encode_path_component(other_room) + "/aliases",
                                    alice);

            THEN("only its own alias is returned")
            {
                REQUIRE(reply.status == 200U);
                REQUIRE(reply.body.find("#two0:example.org") != std::string::npos);
                REQUIRE(reply.body.find("#one0:example.org") == std::string::npos);
            }
        }
    }
}

// C40 (ADR-0688). Spec: Matrix Application Service API v1.19, "Namespaces": an exclusive namespace "prevents humans and
// other application services from creating/deleting entities in that namespace".
// URL: ../../docs/matrix-v1.19-spec/application-service-api.md
SCENARIO("Only the owning application service deletes an alias in its exclusive namespace",
         "[c40][directory][alias][appservice][exclusive]")
{
    GIVEN("a bridge with an exclusive alias namespace and a user who is the recorded creator of an alias in it")
    {
        auto const path = merovingian::tests::unique_temporary_path("merovingian-c40-alias-bridge", ".json");
        auto const registration = write_bridge_registration(path);
        auto started = merovingian::homeserver::start_client_server(caps_config(100U, 100U, registration));
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_and_login(rt, "alice");
        auto const bridge_room = create_room(rt, as_token);
        auto const reserved = alias_name("_alias_bridge_del", 0U);
        auto const bridged = alias_name("_alias_bridge_own", 0U);
        auto const ordinary = alias_name("plain", 0U);
        // The alias was recorded for alice before the registration existed, so creation never refused it.
        REQUIRE(merovingian::database::store_room_alias(rt.homeserver.database.persistent_store,
                                                        {reserved, bridge_room, "@alice:example.org"}));
        REQUIRE(put_alias(rt, as_token, bridged, bridge_room).status == 200U);
        REQUIRE(put_alias(rt, alice, ordinary, create_room(rt, alice)).status == 200U);

        WHEN("the user deletes the reserved alias")
        {
            auto const reply = call(rt, "DELETE", alias_path(reserved), alice);

            THEN("it is refused with 400 M_EXCLUSIVE and the alias stays")
            {
                REQUIRE(reply.status == 400U);
                REQUIRE(errcode_of(reply) == "M_EXCLUSIVE");
                REQUIRE(alias_stored(rt, reserved));
            }
        }

        WHEN("the owning bridge deletes its alias")
        {
            auto const reply = call(rt, "DELETE", alias_path(bridged), as_token);

            THEN("it is deleted")
            {
                REQUIRE(reply.status == 200U);
                REQUIRE_FALSE(alias_stored(rt, bridged));
            }
        }

        WHEN("the user deletes an alias outside the namespace")
        {
            auto const reply = call(rt, "DELETE", alias_path(ordinary), alice);

            THEN("it is deleted as before")
            {
                REQUIRE(reply.status == 200U);
                REQUIRE_FALSE(alias_stored(rt, ordinary));
            }
        }

        std::filesystem::remove(path);
    }
}
