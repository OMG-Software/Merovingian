// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// ingest_send_join_state commits the send_join snapshot in one transaction (review of #541). A
// snapshot may hold two different events for one (event_type, state_key), a join and then a
// leave, say; each prepared its own INSERT into current_state, whose primary key is that tuple,
// so on a backend that runs the SQL the transaction failed and the join with it. The in-memory
// backend runs no SQL, so this runs against SQLite.

#include "../support/master_key.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/room_service.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <string>
#include <variant>

#include <sodium.h>

namespace
{

[[nodiscard]] auto unique_sqlite_path() -> std::filesystem::path
{
    auto const now = std::chrono::steady_clock::now().time_since_epoch().count();
    return std::filesystem::temp_directory_path() /
           ("merovingian-send-join-snapshot-" + std::to_string(now) + ".sqlite3");
}

[[nodiscard]] auto sqlite_config(std::filesystem::path const& path) -> merovingian::config::Config
{
    auto server = merovingian::config::ServerConfig{};
    server.server_name = "local.example.org";
    auto database = merovingian::config::DatabaseConfig{};
    database.backend = merovingian::config::DatabaseBackend::sqlite;
    database.sqlite_path = path.string();
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    return {server,   merovingian::config::ListenersConfig{},        database,
            security, merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{}};
}

[[nodiscard]] auto member_event(std::string const& room_id, std::string const& user, std::string const& membership,
                                int depth) -> std::string
{
    return std::string{R"({"type":"m.room.member","state_key":")"} + user + R"(","room_id":")" + room_id +
           R"(","sender":")" + user + R"(","depth":)" + std::to_string(depth) +
           R"(,"origin_server_ts":1000,"prev_events":[],"auth_events":[],"hashes":{"sha256":"aGFzaA"},)"
           R"("content":{"membership":")" +
           membership + R"("},"signatures":{"remote.example.org":{"ed25519:auto":"aaaa"}}})";
}

} // namespace

SCENARIO("A send_join snapshot with two events for one state key commits on a backend that runs the SQL",
         "[homeserver][federation][send_join][send-join-snapshot]")
{
    GIVEN("a SQLite-backed runtime and a snapshot holding a member's join and then that member's leave")
    {
        REQUIRE(sodium_init() >= 0);
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(sqlite_config(path));
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const room_id = std::string{"!snapshot:remote.example.org"};
        auto const bob = std::string{"@bob:remote.example.org"};
        auto const create = std::string{R"({"type":"m.room.create","state_key":"","room_id":")"} + room_id +
                            R"(","sender":"@alice:remote.example.org","depth":1,"origin_server_ts":1000,)"
                            R"("prev_events":[],"auth_events":[],"hashes":{"sha256":"aGFzaA"},)"
                            R"("content":{"room_version":"10"},)"
                            R"("signatures":{"remote.example.org":{"ed25519:auto":"aaaa"}}})";
        auto snapshot = merovingian::canonicaljson::Array{};
        for (auto const& json : {create, member_event(room_id, bob, "join", 2), member_event(room_id, bob, "leave", 3)})
        {
            auto const parsed = merovingian::canonicaljson::parse_lossless(json);
            REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
            snapshot.push_back(parsed.value);
        }
        auto const policy = *merovingian::rooms::find_room_version_policy("10");

        WHEN("the snapshot is ingested")
        {
            auto const ingested = merovingian::homeserver::ingest_send_join_state(runtime, room_id, snapshot, policy);

            THEN("it commits: all three are counted, bob's key holds the leave, and bob is not joined")
            {
                REQUIRE(ingested.recorded_state_events == snapshot.size());
                REQUIRE(ingested.state_entries.size() == 2U);
                REQUIRE(std::ranges::find(ingested.joined_members, bob) == ingested.joined_members.end());
                auto const& state = runtime.database.persistent_store.state;
                auto const bob_state = std::ranges::find_if(state, [&](auto const& entry) {
                    return entry.room_id == room_id && entry.event_type == "m.room.member" && entry.state_key == bob;
                });
                REQUIRE(bob_state != state.end());
                auto const bob_entry = std::ranges::find_if(ingested.state_entries, [&](auto const& entry) {
                    return entry.event_type == "m.room.member" && entry.state_key == bob;
                });
                REQUIRE(bob_entry != ingested.state_entries.end());
                REQUIRE(bob_state->event_id == bob_entry->event_id);
            }
        }

        std::filesystem::remove(path);
    }
}
