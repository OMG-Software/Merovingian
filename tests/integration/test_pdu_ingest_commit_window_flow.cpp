// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// A federated state event's commit and a local write of the same current-state row must not interleave: what memory
// holds after both equals what the database holds, and a restart serves the same row (run-3 C41, ADR-0696). The
// ingest's commit is held open by an outside SQLite connection holding the write lock, with database.pool_size = 1 so
// the order of the two commits is the order they reach the pool. The assertion is on rows, never on time: the wait
// for the local request to reach its lock only lets the test show the race before the fix.

#include "../support/InMemoryDatabaseConfig.hpp"
#include "../support/JsonTestSupport.hpp"
#include "../support/MasterKey.hpp"
#include "../support/RegistrationToken.hpp"
#include "../support/SqliteCloser.hpp"
#include "merovingian/canonicaljson/CanonicalJsonError.hpp"
#include "merovingian/canonicaljson/Serializer.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/DatabaseBackend.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/SqliteWritePool.hpp"
#include "merovingian/events/EventId.hpp"
#include "merovingian/federation/InboundPduEnvelope.hpp"
#include "merovingian/federation/PduIngestionResult.hpp"
#include "merovingian/federation/PduIngestionStatus.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/LocalHttpRouter.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sqlite3.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace
{

using merovingian::tests::parse_object;
using merovingian::tests::string_member;

[[nodiscard]] auto commit_window_config(std::string const& path) -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    security.federation.enabled = true;
    security.federation.default_policy = "allow";
    auto config = merovingian::config::Config{
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::tests::in_memory_database_config(),
        security,
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
    config.database().backend = merovingian::config::DatabaseBackend::sqlite;
    config.database().sqlite_path = path;
    config.database().pool_size = 1U;
    return config;
}

[[nodiscard]] auto now_ms() -> std::int64_t
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
        .count();
}

[[nodiscard]] auto id_array(std::vector<std::string> const& ids) -> merovingian::canonicaljson::Array
{
    auto array = merovingian::canonicaljson::Array{};
    for (auto const& id : ids)
    {
        array.push_back(merovingian::canonicaljson::Value{id});
    }
    return array;
}

// A room v12 PDU as ingest_pdu_event receives it once its signature has been checked.
[[nodiscard]] auto make_envelope(std::string const& room_id, std::string const& event_id, std::string const& type,
                                 std::string const& state_key, std::string const& sender,
                                 merovingian::canonicaljson::Object content, std::vector<std::string> const& prev,
                                 std::vector<std::string> const& auth, std::uint64_t depth, std::int64_t ts)
    -> merovingian::federation::InboundPduEnvelope
{
    namespace json = merovingian::canonicaljson;
    auto object = json::Object{};
    object.push_back(json::make_member("auth_events", json::Value{id_array(auth)}));
    object.push_back(json::make_member("content", json::Value{std::move(content)}));
    object.push_back(json::make_member("depth", json::Value{static_cast<std::int64_t>(depth)}));
    object.push_back(json::make_member("origin_server_ts", json::Value{ts}));
    object.push_back(json::make_member("prev_events", json::Value{id_array(prev)}));
    object.push_back(json::make_member("room_id", json::Value{room_id}));
    object.push_back(json::make_member("sender", json::Value{sender}));
    object.push_back(json::make_member("state_key", json::Value{state_key}));
    object.push_back(json::make_member("type", json::Value{type}));
    auto const hash = merovingian::events::make_content_hash(json::Value{object});
    REQUIRE(hash.error.empty());
    auto hashes = json::Object{};
    hashes.push_back(json::make_member("sha256", json::Value{hash.sha256}));
    object.push_back(json::make_member("hashes", json::Value{std::move(hashes)}));
    auto const serialized = json::serialize_canonical(json::Value{std::move(object)});
    REQUIRE(serialized.error == json::CanonicalJsonError::none);
    auto envelope = merovingian::federation::InboundPduEnvelope{};
    envelope.event_id = event_id;
    envelope.room_id = room_id;
    envelope.room_version = "12";
    envelope.sender = sender;
    envelope.event_type = type;
    envelope.state_key = state_key;
    envelope.origin_server_ts = ts;
    envelope.depth = depth;
    envelope.prev_event_ids = prev;
    envelope.auth_event_ids = auth;
    envelope.json = serialized.output;
    return envelope;
}

// The room's m.room.topic row as the database holds it, read through a connection of the test's own.
[[nodiscard]] auto database_topic_row(std::string const& path, std::string const& room_id) -> std::string
{
    sqlite3* raw = nullptr;
    REQUIRE(sqlite3_open_v2(path.c_str(), &raw, SQLITE_OPEN_READONLY, nullptr) == SQLITE_OK);
    auto const database = std::unique_ptr<sqlite3, merovingian::tests::SqliteCloser>{raw};
    sqlite3_stmt* statement = nullptr;
    REQUIRE(sqlite3_prepare_v2(raw,
                               "SELECT event_id FROM current_state WHERE room_id = ?1 AND event_type = 'm.room.topic' "
                               "AND state_key = ''",
                               -1, &statement, nullptr) == SQLITE_OK);
    sqlite3_bind_text(statement, 1, room_id.c_str(), -1, nullptr);
    auto row = std::string{"<none>"};
    if (sqlite3_step(statement) == SQLITE_ROW)
    {
        row = reinterpret_cast<char const*>(sqlite3_column_text(statement, 0));
    }
    sqlite3_finalize(statement);
    return row;
}

[[nodiscard]] auto max_depth(merovingian::database::PersistentStore const& store, std::vector<std::string> const& ids)
    -> std::uint64_t
{
    auto depth = std::uint64_t{0U};
    for (auto const& id : ids)
    {
        auto const found = store.events.find(id);
        REQUIRE(found != store.events.end());
        depth = std::max<std::uint64_t>(depth, found->depth);
    }
    return depth;
}

[[nodiscard]] auto memory_topic_row(merovingian::database::PersistentStore const& store, std::string const& room_id)
    -> std::string
{
    return merovingian::database::find_current_state_event_id(store, room_id, "m.room.topic", "").value_or("<none>");
}

} // namespace

SCENARIO("A local state write cannot land inside a federated state event's commit",
         "[integration][pdu_ingestion][commit_window]")
{
    GIVEN("a room where a remote member may set the topic, and an outside writer holding the database's write lock")
    {
        auto const path = (std::filesystem::temp_directory_path() /
                           ("merovingian-commit-window-" +
                            std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + ".sqlite3"))
                              .string();
        auto started = std::optional<merovingian::homeserver::ClientServerStartResult>{};
        started.emplace(merovingian::homeserver::start_client_server(commit_window_config(path)));
        REQUIRE(started->started);
        auto& runtime = started->runtime;
        auto& homeserver = runtime.homeserver;
        merovingian::homeserver::wire_federation_callbacks(homeserver);
        auto& store = homeserver.database.persistent_store;

        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("owner", "CorrectHorse7!")})
                    .response.status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@owner:example.org"},"password":"CorrectHorse7!","device_id":"OWNER"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = *string_member(parse_object(login.response.body), "access_token");
        auto const create = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST", "/_matrix/client/v3/createRoom", token,
             R"({"preset":"public_chat","room_version":"12","topic":"original","power_level_content_override":{"users":{"@alice:remote.example.org":100}}})"});
        REQUIRE(create.response.status == 200U);
        auto const room_id = *string_member(parse_object(create.response.body), "room_id");

        auto const alice = std::string{"@alice:remote.example.org"};
        auto const power_levels =
            *merovingian::database::find_current_state_event_id(store, room_id, "m.room.power_levels", "");
        auto const join_rules =
            *merovingian::database::find_current_state_event_id(store, room_id, "m.room.join_rules", "");
        auto tips = merovingian::database::find_forward_extremities(store, room_id);
        auto join_content = merovingian::canonicaljson::Object{};
        join_content.push_back(merovingian::canonicaljson::make_member(
            "membership", merovingian::canonicaljson::Value{std::string{"join"}}));
        auto const join_id = std::string{"$commit-window-alice-join"};
        REQUIRE(merovingian::homeserver::ingest_pdu_event(
                    homeserver, make_envelope(room_id, join_id, "m.room.member", alice, alice, std::move(join_content),
                                              tips, {power_levels, join_rules}, max_depth(store, tips) + 1U, now_ms()))
                    .status == merovingian::federation::PduIngestionStatus::accepted);

        tips = merovingian::database::find_forward_extremities(store, room_id);
        auto topic_content = merovingian::canonicaljson::Object{};
        topic_content.push_back(
            merovingian::canonicaljson::make_member("topic", merovingian::canonicaljson::Value{std::string{"remote"}}));
        auto const remote_topic =
            make_envelope(room_id, "$commit-window-remote-topic", "m.room.topic", "", alice, std::move(topic_content),
                          tips, {power_levels, join_id}, max_depth(store, tips) + 1U, now_ms() + 60'000);

        sqlite3* raw_blocker = nullptr;
        REQUIRE(sqlite3_open(path.c_str(), &raw_blocker) == SQLITE_OK);
        auto blocker = std::unique_ptr<sqlite3, merovingian::tests::SqliteCloser>{raw_blocker};
        REQUIRE(sqlite3_exec(raw_blocker, "BEGIN IMMEDIATE", nullptr, nullptr, nullptr) == SQLITE_OK);

        WHEN("the federated topic change is committing and a local client sets the topic")
        {
            auto ingest_status = std::atomic<int>{-1};
            auto local_status = std::atomic<int>{-1};
            auto ingest = std::thread{[&] {
                ingest_status.store(
                    static_cast<int>(merovingian::homeserver::ingest_pdu_event(homeserver, remote_topic).status));
            }};
            // The ingest holds the pool's only connection once it is inside its commit.
            while (store.sqlite_write_pool->pool.in_use() == 0U && ingest_status.load() == -1)
            {
                std::this_thread::yield();
            }
            auto local = std::thread{[&] {
                local_status.store(
                    static_cast<int>(merovingian::homeserver::handle_client_server_request(
                                         runtime, {"PUT", "/_matrix/client/v3/rooms/" + room_id + "/state/m.room.topic",
                                                   token, R"({"topic":"local"})"})
                                         .response.status));
            }};
            // Lets the local request reach the point it waits at; the outcome is asserted on rows below, not on time.
            std::this_thread::sleep_for(std::chrono::milliseconds{300});
            auto const released = sqlite3_exec(raw_blocker, "ROLLBACK", nullptr, nullptr, nullptr);
            blocker.reset();
            ingest.join();
            local.join();
            auto const memory_row = memory_topic_row(store, room_id);
            auto const database_row = database_topic_row(path, room_id);
            started.reset();
            auto restarted = merovingian::homeserver::start_client_server(commit_window_config(path));
            auto const restarted_row =
                restarted.started ? memory_topic_row(restarted.runtime.homeserver.database.persistent_store, room_id)
                                  : std::string{};

            THEN("both writes succeed, memory holds what the database holds, and a restart serves the same row")
            {
                REQUIRE(released == SQLITE_OK);
                REQUIRE(ingest_status.load() ==
                        static_cast<int>(merovingian::federation::PduIngestionStatus::accepted));
                REQUIRE(local_status.load() == 200);
                REQUIRE(memory_row == database_row);
                REQUIRE(restarted.started);
                REQUIRE(restarted_row == memory_row);
            }
        }
        std::filesystem::remove(path);
    }
}
