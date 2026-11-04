// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
// P6 (ADR-0442). Start-up used to scan every room for every event and every join, and each room held a second
// copy of every event's JSON beside the event table. The event table is now the only copy: these scenarios pin
// that a restart rebuilds the same rooms, members and reads, and that a stored, redacted and reloaded event is
// served from that one copy.

#include "../support/e2ee_caps_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "../support/temp_directory.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/runtime.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace
{

using merovingian::homeserver::ClientServerRuntime;

[[nodiscard]] auto sqlite_config(std::filesystem::path const& sqlite_path) -> merovingian::config::Config
{
    auto database = merovingian::config::DatabaseConfig{};
    database.backend = merovingian::config::DatabaseBackend::sqlite;
    database.sqlite_path = sqlite_path.string();
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    return {
        merovingian::config::ServerConfig{},           merovingian::config::ListenersConfig{},  database, security,
        merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto call(ClientServerRuntime& runtime, std::string method, std::string path, std::string const& token,
                        std::string body = {}) -> merovingian::homeserver::LocalHttpResponse
{
    return merovingian::homeserver::handle_client_server_request(
               runtime, {std::move(method), std::move(path), token, std::move(body)})
        .response;
}

[[nodiscard]] auto login(ClientServerRuntime& runtime, std::string const& localpart) -> std::string
{
    auto const response = call(runtime, "POST", "/_matrix/client/v3/login", {},
                               R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@)" + localpart +
                                   R"(:example.org"},"password":"CorrectHorse7!","device_id":"DEV"})");
    REQUIRE(response.status == 200U);
    return merovingian::tests::access_token_from(response.body);
}

[[nodiscard]] auto register_and_login(ClientServerRuntime& runtime, std::string const& localpart) -> std::string
{
    auto const registered = call(runtime, "POST", "/_matrix/client/v3/register", {},
                                 merovingian::tests::registration_json(localpart, "CorrectHorse7!"));
    REQUIRE(registered.status == 200U);
    return login(runtime, localpart);
}

[[nodiscard]] auto messages_of(ClientServerRuntime& runtime, std::string const& token, std::string const& room_id)
    -> std::string
{
    auto const response =
        call(runtime, "GET", "/_matrix/client/v3/rooms/" + room_id + "/messages?dir=b&limit=50", token);
    REQUIRE(response.status == 200U);
    return response.body;
}

[[nodiscard]] auto sorted_members(ClientServerRuntime const& runtime, std::string const& room_id)
    -> std::vector<std::string>
{
    auto const& rooms = runtime.homeserver.database.rooms;
    auto const room = std::ranges::find(rooms, room_id, &merovingian::homeserver::LocalRoom::room_id);
    REQUIRE(room != rooms.end());
    auto members = room->members;
    std::ranges::sort(members);
    return members;
}

} // namespace

SCENARIO("a restart rebuilds the same rooms, members and message history from the event table",
         "[homeserver][startup][persistence][room-events][p6]")
{
    GIVEN("a SQLite-backed server with two rooms, three members and some messages")
    {
        auto const sqlite_path =
            merovingian::tests::temporary_directory() /
            ("merovingian-room-events-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) +
             ".sqlite3");
        auto room_one = std::string{};
        auto room_two = std::string{};
        auto members_one = std::vector<std::string>{};
        auto members_two = std::vector<std::string>{};
        auto history_one = std::string{};
        auto history_two = std::string{};
        auto room_count = std::size_t{0U};
        {
            auto started = merovingian::homeserver::start_client_server(sqlite_config(sqlite_path));
            REQUIRE(started.started);
            auto& runtime = started.runtime;
            auto const alice = register_and_login(runtime, "alice");
            auto const bob = register_and_login(runtime, "bob");
            auto const carol = register_and_login(runtime, "carol");
            room_one = merovingian::tests::string_field(
                call(runtime, "POST", "/_matrix/client/v3/createRoom", alice, R"({"preset":"public_chat"})").body,
                "room_id");
            room_two = merovingian::tests::string_field(
                call(runtime, "POST", "/_matrix/client/v3/createRoom", alice, R"({"preset":"public_chat"})").body,
                "room_id");
            REQUIRE(call(runtime, "POST", "/_matrix/client/v3/join/" + room_one, bob, "{}").status == 200U);
            REQUIRE(call(runtime, "POST", "/_matrix/client/v3/join/" + room_one, carol, "{}").status == 200U);
            REQUIRE(call(runtime, "POST", "/_matrix/client/v3/join/" + room_two, carol, "{}").status == 200U);
            REQUIRE(call(runtime, "PUT", "/_matrix/client/v3/rooms/" + room_one + "/send/m.room.message/a", alice,
                         R"({"msgtype":"m.text","body":"first"})")
                        .status == 200U);
            REQUIRE(call(runtime, "PUT", "/_matrix/client/v3/rooms/" + room_one + "/send/m.room.message/b", bob,
                         R"({"msgtype":"m.text","body":"second"})")
                        .status == 200U);
            REQUIRE(call(runtime, "PUT", "/_matrix/client/v3/rooms/" + room_two + "/send/m.room.message/c", carol,
                         R"({"msgtype":"m.text","body":"elsewhere"})")
                        .status == 200U);
            members_one = sorted_members(runtime, room_one);
            members_two = sorted_members(runtime, room_two);
            history_one = messages_of(runtime, alice, room_one);
            history_two = messages_of(runtime, carol, room_two);
            room_count = runtime.homeserver.database.rooms.size();
        }

        WHEN("a new runtime starts against the same database")
        {
            auto restarted = merovingian::homeserver::start_client_server(sqlite_config(sqlite_path));
            REQUIRE(restarted.started);
            auto& runtime = restarted.runtime;
            auto const alice = login(runtime, "alice");
            auto const carol = login(runtime, "carol");

            THEN("it holds the same rooms with the same members, each once")
            {
                CHECK(runtime.homeserver.database.rooms.size() == room_count);
                CHECK(sorted_members(runtime, room_one) == members_one);
                CHECK(sorted_members(runtime, room_two) == members_two);
                CHECK(members_one.size() == 3U);
                CHECK(members_two.size() == 2U);
            }
            THEN("each room's history reads exactly as before")
            {
                CHECK(messages_of(runtime, alice, room_one) == history_one);
                CHECK(messages_of(runtime, carol, room_two) == history_two);
            }
        }

        auto ignored = std::error_code{};
        std::filesystem::remove(sqlite_path, ignored);
    }
}

SCENARIO("a redacted event is served redacted, before and after a restart",
         "[homeserver][startup][persistence][room-events][redaction][p6]")
{
    GIVEN("a SQLite-backed room holding a message that its sender then redacts")
    {
        auto const sqlite_path =
            merovingian::tests::temporary_directory() /
            ("merovingian-room-redaction-" +
             std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + ".sqlite3");
        auto room_id = std::string{};
        auto event_id = std::string{};
        auto before_restart = std::string{};
        {
            auto started = merovingian::homeserver::start_client_server(sqlite_config(sqlite_path));
            REQUIRE(started.started);
            auto& runtime = started.runtime;
            auto const alice = register_and_login(runtime, "alice");
            room_id = merovingian::tests::string_field(
                call(runtime, "POST", "/_matrix/client/v3/createRoom", alice, R"({"preset":"private_chat"})").body,
                "room_id");
            auto const sent = call(runtime, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/a",
                                   alice, R"({"msgtype":"m.text","body":"secret words"})");
            REQUIRE(sent.status == 200U);
            event_id = merovingian::tests::string_field(sent.body, "event_id");
            auto const stored =
                call(runtime, "GET", "/_matrix/client/v3/rooms/" + room_id + "/event/" + event_id, alice);
            REQUIRE(stored.status == 200U);
            REQUIRE(stored.body.find("secret words") != std::string::npos);

            REQUIRE(call(runtime, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/redact/" + event_id + "/r1", alice,
                         R"({"reason":"oops"})")
                        .status == 200U);
            auto const redacted =
                call(runtime, "GET", "/_matrix/client/v3/rooms/" + room_id + "/event/" + event_id, alice);
            REQUIRE(redacted.status == 200U);
            before_restart = redacted.body;
        }

        WHEN("the event is read after the redaction and again after a restart")
        {
            auto restarted = merovingian::homeserver::start_client_server(sqlite_config(sqlite_path));
            REQUIRE(restarted.started);
            auto& runtime = restarted.runtime;
            auto const alice = login(runtime, "alice");
            auto const after_restart =
                call(runtime, "GET", "/_matrix/client/v3/rooms/" + room_id + "/event/" + event_id, alice);
            auto const timeline = messages_of(runtime, alice, room_id);

            THEN("the redacted JSON is what is served: the body is gone in every read")
            {
                CHECK(before_restart.find("secret words") == std::string::npos);
                REQUIRE(after_restart.status == 200U);
                CHECK(after_restart.body.find("secret words") == std::string::npos);
                CHECK(timeline.find("secret words") == std::string::npos);
                CHECK(timeline.find(event_id) != std::string::npos);
            }
            THEN("the event table holds one row for it, and it is the redacted one")
            {
                auto const& events = runtime.homeserver.database.persistent_store.events;
                auto const row = events.find(event_id);
                REQUIRE(row != events.end());
                CHECK(row->json.find("secret words") == std::string::npos);
            }
        }

        WHEN("the room is reloaded from the database, as a worker's snapshot refresh does")
        {
            auto started = merovingian::homeserver::start_client_server(sqlite_config(sqlite_path));
            REQUIRE(started.started);
            auto& runtime = started.runtime;
            auto const alice = login(runtime, "alice");
            REQUIRE(merovingian::database::reload_room(runtime.homeserver.database.persistent_store, room_id));
            auto const reloaded =
                call(runtime, "GET", "/_matrix/client/v3/rooms/" + room_id + "/event/" + event_id, alice);

            THEN("the reloaded event is still the redacted one")
            {
                REQUIRE(reloaded.status == 200U);
                CHECK(reloaded.body.find("secret words") == std::string::npos);
            }
        }

        auto ignored = std::error_code{};
        std::filesystem::remove(sqlite_path, ignored);
    }
}
