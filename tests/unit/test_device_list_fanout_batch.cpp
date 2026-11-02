// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/in_memory_database_config.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/runtime.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <algorithm>
#include <cstdint>
#include <set>
#include <string>
#include <tuple>
#include <vector>

// Audit run-2 F-04. Spec: Matrix Client-Server API v1.19, "Tracking the device list for a user":
// `device_lists.changed` is how a client learns of a change, so only a local user has anything to be
// told; a remote user's server learns through m.device_list_update. One request records one batch:
// one stream position and one commit, however large a remote server has made the room's roster.

namespace
{

[[nodiscard]] auto registration_enabled_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    return merovingian::config::Config{
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::tests::in_memory_database_config(),
        security,
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto json_string_after(std::string const& body, std::string const& key) -> std::string
{
    auto const needle = "\"" + key + "\":\"";
    auto const begin = body.find(needle);
    REQUIRE(begin != std::string::npos);
    auto const value_begin = begin + needle.size();
    auto const value_end = body.find('"', value_begin);
    REQUIRE(value_end != std::string::npos);
    return body.substr(value_begin, value_end - value_begin);
}

struct LoggedInUser final
{
    std::string token{};
    std::string device_id{};
};

[[nodiscard]] auto register_user(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& name)
    -> LoggedInUser
{
    auto const registered = merovingian::homeserver::handle_client_server_request(
        runtime,
        {"POST", "/_matrix/client/v3/register", {}, merovingian::tests::registration_json(name, "CorrectHorse7!")});
    REQUIRE(registered.response.status == 200U);
    auto const device_id = name + "_DEVICE";
    auto const login = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST",
                  "/_matrix/client/v3/login",
                  {},
                  R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@)" + name +
                      R"(:example.org"},"password":"CorrectHorse7!","device_id":")" + device_id + R"("})"});
    REQUIRE(login.response.status == 200U);
    return {json_string_after(login.response.body, "access_token"), device_id};
}

auto join_room_with(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& owner_token,
                    std::string const& joiner_token, std::string const& joiner_id) -> std::string
{
    auto const room = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST", "/_matrix/client/v3/createRoom", owner_token,
                  R"({"preset":"public_chat","room_version":"11","invite":[")" + joiner_id + R"("]})"});
    REQUIRE(room.response.status == 200U);
    auto const room_id = json_string_after(room.response.body, "room_id");
    auto const joined = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/join", joiner_token, "{}"});
    REQUIRE(joined.response.status == 200U);
    return room_id;
}

// A federated room's roster: `count` members chosen by a remote server.
auto add_remote_members(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& room_id, int count)
    -> void
{
    auto& rooms = runtime.homeserver.database.rooms;
    auto const room = std::ranges::find_if(rooms, [&](auto const& candidate) {
        return candidate.room_id == room_id;
    });
    REQUIRE(room != rooms.end());
    for (auto index = 0; index < count; ++index)
    {
        room->members.push_back("@remote" + std::to_string(index) + ":remote.example.org");
    }
}

[[nodiscard]] auto rows_about(merovingian::homeserver::ClientServerRuntime const& runtime, std::string const& subject)
    -> std::vector<merovingian::database::PersistentDeviceListChange>
{
    auto rows = std::vector<merovingian::database::PersistentDeviceListChange>{};
    for (auto const& row : runtime.homeserver.database.persistent_store.device_list_changes)
    {
        if (row.subject_user_id == subject)
        {
            rows.push_back(row);
        }
    }
    return rows;
}

} // namespace

SCENARIO("A device or key change records one batch for local observers only", "[device-lists][security][key-api]")
{
    GIVEN("alice and bob sharing two rooms, one of them with a large remote roster")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = register_user(runtime, "alice");
        auto const bob = register_user(runtime, "bob");
        auto const first_room = join_room_with(runtime, bob.token, alice.token, "@alice:example.org");
        std::ignore = join_room_with(runtime, bob.token, alice.token, "@alice:example.org");
        add_remote_members(runtime, first_room, 200);
        auto& store = runtime.homeserver.database.persistent_store;

        struct Trigger final
        {
            std::string method{};
            std::string path{};
            std::string body{};
            bool notifies_self{false};
        };
        auto const trigger = GENERATE_COPY(
            Trigger{"POST", "/_matrix/client/v3/keys/signatures/upload", "{}", true},
            Trigger{"PUT", "/_matrix/client/v3/devices/" + alice.device_id, R"({"display_name":"renamed"})", false},
            Trigger{"POST", "/_matrix/client/v3/logout", "{}", false},
            Trigger{
                "POST", "/_matrix/client/v3/keys/upload",
                R"({"device_keys":{"user_id":"@alice:example.org","device_id":")" + alice.device_id +
                    R"(","algorithms":["m.olm.v1.curve25519-aes-sha2","m.megolm.v1.aes-sha2"],"keys":{"curve25519:)" +
                    alice.device_id + R"(":"curve25519-public","ed25519:)" + alice.device_id +
                    R"(":"ed25519-public"},"signatures":{}},"one_time_keys":{}})",
                true});

        WHEN("alice makes the change: " + trigger.method + " " + trigger.path)
        {
            store.device_list_changes.clear();
            auto const counter_before = store.next_sync_stream_id;

            auto const answered = merovingian::homeserver::handle_client_server_request(
                runtime, {trigger.method, trigger.path, alice.token, trigger.body});
            REQUIRE(answered.response.status == 200U);

            THEN("no row names a remote observer")
            {
                auto const rows = rows_about(runtime, "@alice:example.org");
                REQUIRE(std::ranges::none_of(rows, [](auto const& row) {
                    return row.observer_user_id.ends_with(":remote.example.org");
                }));
            }

            THEN("bob is told once, even though he shares two rooms with her")
            {
                auto const rows = rows_about(runtime, "@alice:example.org");
                REQUIRE(std::ranges::count_if(rows, [](auto const& row) {
                            return row.observer_user_id == "@bob:example.org";
                        }) == 1);
            }

            THEN("alice's own row is there exactly when this change is one her other devices track")
            {
                auto const rows = rows_about(runtime, "@alice:example.org");
                auto const self_rows = std::ranges::count_if(rows, [](auto const& row) {
                    return row.observer_user_id == "@alice:example.org";
                });
                REQUIRE(self_rows == (trigger.notifies_self ? 1 : 0));
            }

            THEN("every row carries one stream position, so the batch was one commit")
            {
                auto positions = std::set<std::uint64_t>{};
                for (auto const& row : rows_about(runtime, "@alice:example.org"))
                {
                    positions.insert(row.stream_id);
                }
                REQUIRE(positions.size() == 1U);
                REQUIRE(*positions.begin() > counter_before);
            }
        }
    }
}
