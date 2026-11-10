// SPDX-License-Identifier: GPL-3.0-or-later
#include "../federation_signing_test_support.hpp"
#include "../support/in_memory_database_config.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "../support/temp_directory.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/database/ExaminedRows.hpp"
#include "merovingian/database/PersistentDevice.hpp"
#include "merovingian/database/PersistentPresence.hpp"
#include "merovingian/database/PersistentProfile.hpp"
#include "merovingian/database/PersistentStateEvent.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/PersistentStoreOpenResult.hpp"
#include "merovingian/database/migration.hpp"
#include "merovingian/database/schema.hpp"
#include "merovingian/federation/ResolvedAddressSet.hpp"
#include "merovingian/federation/ServerDiscoveryNetwork.hpp"
#include "merovingian/federation/SrvRecord.hpp"
#include "merovingian/federation/WellKnownServerResult.hpp"
#include "merovingian/federation/inbound_request.hpp"
#include "merovingian/federation/outbound_transaction.hpp"
#include "merovingian/homeserver/ClientServerClock.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/HttpConnectionDispatcher.hpp"
#include "merovingian/homeserver/HttpServeStats.hpp"
#include "merovingian/homeserver/KeyServerCache.hpp"
#include "merovingian/homeserver/LocalDatabase.hpp"
#include "merovingian/homeserver/LocalHttpResponse.hpp"
#include "merovingian/homeserver/RuntimeStartResult.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/http_server.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/room_service.hpp"
#include "merovingian/observability/LogLevel.hpp"
#include "merovingian/observability/SingleLog.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sqlite3.h>

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <type_traits>
#include <vector>

namespace
{

class TestSqliteConnection final
{
public:
    explicit TestSqliteConnection(std::filesystem::path const& path)
    {
        std::ignore = sqlite3_open(path.string().c_str(), &connection_);
    }

    TestSqliteConnection(TestSqliteConnection const& other) = delete;
    auto operator=(TestSqliteConnection const& other) -> TestSqliteConnection& = delete;
    TestSqliteConnection(TestSqliteConnection&& other) noexcept = delete;
    auto operator=(TestSqliteConnection&& other) noexcept -> TestSqliteConnection& = delete;

    ~TestSqliteConnection()
    {
        sqlite3_close(connection_);
    }

    [[nodiscard]] auto execute(std::string const& sql) const -> bool
    {
        auto* error = static_cast<char*>(nullptr);
        auto const ok = sqlite3_exec(connection_, sql.c_str(), nullptr, nullptr, &error) == SQLITE_OK;
        sqlite3_free(error);
        return ok;
    }

private:
    sqlite3* connection_{nullptr};
};

[[nodiscard]] auto unique_sqlite_path(std::string const& suffix) -> std::filesystem::path
{
    auto const now = std::chrono::steady_clock::now().time_since_epoch().count();
    return merovingian::tests::temporary_directory() /
           ("merovingian-review-" + suffix + "-" + std::to_string(now) + ".sqlite3");
}

} // namespace

SCENARIO("Runtime membership projection ignores non-joined invite and knock updates",
         "[homeserver][review][membership]")
{
    GIVEN("a local room whose joined-members projection already contains the same user")
    {
        auto database = merovingian::homeserver::LocalDatabase{};
        database.rooms.push_back({"!room:example.org", "@alice:example.org", {"@bob:example.org"}, {}});

        WHEN("invite and knock membership updates are applied to the runtime projection")
        {
            merovingian::homeserver::apply_runtime_membership(database, "!room:example.org", "@bob:example.org",
                                                              "invite");
            merovingian::homeserver::apply_runtime_membership(database, "!room:example.org", "@bob:example.org",
                                                              "knock");

            THEN("the joined-members projection is unchanged")
            {
                REQUIRE(database.rooms.size() == 1U);
                REQUIRE(database.rooms.front().members.size() == 1U);
                REQUIRE(database.rooms.front().members.front() == "@bob:example.org");
            }
        }
    }
}

SCENARIO("Migration planning rejects unsupported future versions without iterating", "[database][migration][review]")
{
    GIVEN("a far future schema version")
    {
        auto const future_version = merovingian::database::current_schema_version() + 1000000U;

        WHEN("a migration plan is requested")
        {
            auto const plan = merovingian::database::migration_plan_between(future_version, 0U);
            auto const validation = merovingian::database::migration_plan_is_valid(plan);

            THEN("the unsupported range is represented as an invalid bounded plan")
            {
                REQUIRE(plan.current_version == future_version);
                REQUIRE(plan.target_version == 0U);
                REQUIRE(plan.steps.empty());
                REQUIRE_FALSE(validation.valid);
                REQUIRE(validation.reason == "migration plan has no steps");
            }
        }
    }
}

SCENARIO("Migration application reapplies upgrade statements after downgrade", "[database][migration][review]")
{
    GIVEN("a schema upgraded, downgraded, and then upgraded again")
    {
        auto const upgraded = merovingian::database::apply_migration_plan(
            {}, merovingian::database::migration_plan_between(0U, merovingian::database::current_schema_version()));
        REQUIRE(upgraded.ok);
        auto const downgraded = merovingian::database::apply_migration_plan(
            upgraded.state,
            merovingian::database::migration_plan_between(merovingian::database::current_schema_version(), 0U));
        REQUIRE(downgraded.ok);

        WHEN("the schema is upgraded again")
        {
            auto const reapplied = merovingian::database::apply_migration_plan(
                downgraded.state,
                merovingian::database::migration_plan_between(0U, merovingian::database::current_schema_version()));

            THEN("tables are recreated even though migration history still contains the old upgrade record")
            {
                REQUIRE(reapplied.ok);
                REQUIRE(reapplied.state.version == merovingian::database::current_schema_version());
                REQUIRE(reapplied.state.tables.size() == merovingian::database::current_schema_tables().size());
            }
        }
    }
}

SCENARIO("Persistent store records insert statements only for accepted user and device rows",
         "[database][persistence][review]")
{
    GIVEN("an opened persistent store")
    {
        auto opened = merovingian::database::open_persistent_store();
        REQUIRE(opened.ok);
        auto& store = opened.store;
        // AUTH-11: the store keeps no committed statements unless capture is enabled.
        merovingian::database::enable_statement_capture(store, 256U);

        WHEN("duplicate users and devices are stored")
        {
            auto const first_user = merovingian::database::store_user(
                store, {"@alice:example.org", "password-hash:v1:1", false, false, true});
            auto const duplicate_user = merovingian::database::store_user(
                store, {"@alice:example.org", "password-hash:v1:2", false, false, false});
            auto const first_device =
                merovingian::database::store_device(store, {"@alice:example.org", "DEVICE1", "Alice laptop"});
            auto const duplicate_device =
                merovingian::database::store_device(store, {"@alice:example.org", "DEVICE1", "Duplicate laptop"});

            THEN("rejected duplicates do not leave replay statements behind")
            {
                REQUIRE(first_user);
                REQUIRE_FALSE(duplicate_user);
                REQUIRE(first_device);
                REQUIRE_FALSE(duplicate_device);
                REQUIRE(store.users.size() == 1U);
                REQUIRE(store.devices.size() == 1U);
                REQUIRE(store.captured_statements.size() == 2U);
                REQUIRE(store.captured_statements[0].name == "insert_user");
                REQUIRE(store.captured_statements[1].name == "insert_device");
            }
        }
    }
}

SCENARIO("Persistent store rejects duplicate token hashes before recording inserts", "[database][persistence][review]")
{
    GIVEN("an opened persistent store")
    {
        auto opened = merovingian::database::open_persistent_store();
        REQUIRE(opened.ok);
        auto& store = opened.store;
        // AUTH-11: the store keeps no committed statements unless capture is enabled.
        merovingian::database::enable_statement_capture(store, 256U);

        WHEN("the same token hash is stored twice")
        {
            auto const first = merovingian::database::store_access_token(
                store, {"@alice:example.org", "DEVICE1", "token-hash:v2:abc", false, std::nullopt});
            auto const duplicate = merovingian::database::store_access_token(
                store, {"@alice:example.org", "DEVICE1", "token-hash:v2:abc", false, std::nullopt});

            THEN("only one token row and statement are recorded")
            {
                REQUIRE(first);
                REQUIRE_FALSE(duplicate);
                REQUIRE(store.access_tokens.size() == 1U);
                REQUIRE(store.captured_statements.size() == 1U);
                REQUIRE(store.captured_statements.front().name == "insert_access_token");
            }
        }
    }
}

SCENARIO("Persistent store commits login device and token rows atomically",
         "[database][persistence][transaction][review]")
{
    GIVEN("an opened persistent store")
    {
        auto opened = merovingian::database::open_persistent_store();
        REQUIRE(opened.ok);
        auto& store = opened.store;
        // AUTH-11: the store keeps no committed statements unless capture is enabled.
        merovingian::database::enable_statement_capture(store, 256U);

        WHEN("a login transaction is attempted with an invalid token hash")
        {
            auto const rejected = merovingian::database::store_device_and_access_token(
                store, merovingian::database::PersistentDevice{"@alice:example.org", "DEVICE1", "Alice laptop"},
                {"@alice:example.org", "DEVICE1", "plaintext", false, std::nullopt});

            THEN("neither durable side effect is recorded")
            {
                REQUIRE_FALSE(rejected);
                REQUIRE(store.devices.empty());
                REQUIRE(store.access_tokens.empty());
                REQUIRE(store.captured_statements.empty());
            }
        }

        WHEN("a login transaction has a new device and hashed token")
        {
            auto const stored = merovingian::database::store_device_and_access_token(
                store, merovingian::database::PersistentDevice{"@alice:example.org", "DEVICE1", "Alice laptop"},
                {"@alice:example.org", "DEVICE1", "token-hash:v2:abc", false, std::nullopt});

            THEN("the device and access token become visible together")
            {
                REQUIRE(stored);
                REQUIRE(store.devices.size() == 1U);
                REQUIRE(store.access_tokens.size() == 1U);
                REQUIRE(store.captured_statements.size() == 2U);
                REQUIRE(store.captured_statements[0].name == "insert_device");
                REQUIRE(store.captured_statements[1].name == "insert_access_token");
            }
        }
    }
}

SCENARIO("Persistent store commits room and state-event rows atomically",
         "[database][persistence][transaction][review]")
{
    GIVEN("an opened persistent store")
    {
        auto opened = merovingian::database::open_persistent_store();
        REQUIRE(opened.ok);
        auto& store = opened.store;
        // AUTH-11: the store keeps no committed statements unless capture is enabled.
        merovingian::database::enable_statement_capture(store, 256U);

        WHEN("a room and state event are stored through transaction helpers")
        {
            auto const room_stored = merovingian::database::store_room_with_membership(
                store, {"!room1:example.org", "@alice:example.org"}, {"!room1:example.org", "@alice:example.org"});
            auto const event_stored = merovingian::database::store_event_with_state(
                store,
                {"$event1:example.org", "!room1:example.org", "@alice:example.org",
                 R"({"type":"m.room.member","state_key":"@alice:example.org"})"},
                merovingian::database::PersistentStateEvent{"!room1:example.org", "m.room.member", "@alice:example.org",
                                                            "$event1:example.org"});

            THEN("the related rows and replay statements are all-or-nothing")
            {
                REQUIRE(room_stored);
                REQUIRE(event_stored);
                REQUIRE(store.rooms.size() == 1U);
                REQUIRE(store.memberships.size() == 1U);
                REQUIRE(store.events.size() == 1U);
                REQUIRE(store.state.size() == 1U);
                REQUIRE(store.state_transitions.size() == 1U);
                // State-event storage now records both current_state and state_transitions.
                REQUIRE(store.captured_statements.size() == 5U);
            }
        }
    }
}

SCENARIO("SQLite persistent transactions roll back failed statement groups",
         "[database][sqlite][persistence][transaction][review]")
{
    GIVEN("a SQLite store and a transaction with a duplicate room insert")
    {
        auto const sqlite_path = unique_sqlite_path("rollback");
        std::filesystem::remove(sqlite_path);
        auto opened = merovingian::database::open_sqlite_persistent_store(sqlite_path.string());
        REQUIRE(opened.ok);
        auto& store = opened.store;
        // AUTH-11: the store keeps no committed statements unless capture is enabled.
        merovingian::database::enable_statement_capture(store, 256U);
        auto const statements = std::vector<merovingian::database::PreparedStatement>{
            {"insert_room",
             "INSERT INTO rooms (room_id, creator_user_id) VALUES ($1, $2)", {{"!room1:example.org", false}, {"@alice:example.org", false}}},
            {"insert_room_duplicate",
             "INSERT INTO rooms (room_id, creator_user_id) VALUES ($1, $2)", {{"!room1:example.org", false}, {"@bob:example.org", false}}  },
        };

        WHEN("the transaction is committed")
        {
            auto const committed = merovingian::database::commit_persistent_transaction(store, statements);
            auto reopened = merovingian::database::open_sqlite_persistent_store(sqlite_path.string());
            REQUIRE(reopened.ok);

            THEN("the first insert is rolled back with the failing insert")
            {
                REQUIRE_FALSE(committed);
                // `restore_sync_stream_id()` may have persisted the sync-stream watermark
                // on startup; any such housekeeping statement is unrelated to this transaction.
                auto const transaction_statements = std::ranges::count_if(
                    store.captured_statements, [](merovingian::database::PreparedStatement const& statement) {
                        return statement.name != "upsert_sync_stream_watermark";
                    });
                REQUIRE(transaction_statements == 0U);
                REQUIRE(reopened.store.rooms.empty());
            }
        }

        std::filesystem::remove(sqlite_path);
    }
}

// Complement run 10 (F14): a federated join answered 500 "initial join state
// persistence failed" under load with nothing in the log to say why. A SQLite
// write that fails now says which stage failed, which statement, and SQLite's
// own error, never the bound values (src/database/AGENTS.md rule 2).
SCENARIO("A failed SQLite transaction is logged with its stage, statement and SQLite error",
         "[database][sqlite][persistence][transaction][observability]")
{
    GIVEN("a SQLite store and a transaction whose second insert repeats the first room's ID")
    {
        auto const sqlite_path = unique_sqlite_path("logged-rollback");
        std::filesystem::remove(sqlite_path);
        auto opened = merovingian::database::open_sqlite_persistent_store(sqlite_path.string());
        REQUIRE(opened.ok);
        auto& store = opened.store;
        auto const statements = std::vector<merovingian::database::PreparedStatement>{
            {"insert_room",
             "INSERT INTO rooms (room_id, creator_user_id) VALUES ($1, $2)", {{"!logged:example.org", false}, {"@alice:example.org", false}}},
            {"insert_room_duplicate",
             "INSERT INTO rooms (room_id, creator_user_id) VALUES ($1, $2)", {{"!logged:example.org", false}, {"@bob:example.org", false}}  },
        };

        WHEN("the transaction is committed")
        {
            auto& logger = merovingian::observability::SingleLog::instance();
            REQUIRE_FALSE(logger.writers_started());
            auto const previous_level = logger.exchange_console_log_level(merovingian::observability::LogLevel::info);
            auto output = std::ostringstream{};
            auto* const previous_buffer = std::cout.rdbuf(output.rdbuf());
            auto const committed = merovingian::database::commit_persistent_transaction(store, statements);
            std::cout.rdbuf(previous_buffer);
            std::ignore = logger.exchange_console_log_level(previous_level);
            auto const logged = output.str();

            THEN("it fails and a warning names the statement and SQLite's constraint error, without the values")
            {
                REQUIRE_FALSE(committed);
                auto lines = std::istringstream{logged};
                auto warning = std::string{};
                for (auto line = std::string{}; std::getline(lines, line);)
                {
                    if (line.find("<WARNING>") != std::string::npos &&
                        line.find("transaction.failed") != std::string::npos)
                    {
                        warning = line;
                    }
                }
                INFO("log: " << logged);
                REQUIRE_FALSE(warning.empty());
                REQUIRE(warning.find("stage=statement") != std::string::npos);
                REQUIRE(warning.find("statement=insert_room_duplicate") != std::string::npos);
                REQUIRE(warning.find("sqlite_code=") != std::string::npos);
                REQUIRE(warning.find("constraint") != std::string::npos);
                REQUIRE(warning.find("@bob:example.org") == std::string::npos);
                REQUIRE(warning.find("!logged:example.org") == std::string::npos);
            }
        }

        std::filesystem::remove(sqlite_path);
    }
}

SCENARIO("SQLite hydration fails closed when a row reader cannot be prepared",
         "[database][sqlite][persistence][review]")
{
    GIVEN("a SQLite store whose users table no longer matches the expected row shape")
    {
        auto const sqlite_path = unique_sqlite_path("hydrate");
        std::filesystem::remove(sqlite_path);
        auto initialized = merovingian::database::open_sqlite_persistent_store(sqlite_path.string());
        REQUIRE(initialized.ok);
        auto connection = TestSqliteConnection{sqlite_path};
        REQUIRE(connection.execute("ALTER TABLE users RENAME TO users_bad"));
        REQUIRE(connection.execute("CREATE TABLE users (user_id TEXT PRIMARY KEY)"));

        WHEN("the persistent store is opened again")
        {
            auto reopened = merovingian::database::open_sqlite_persistent_store(sqlite_path.string());

            THEN("startup rejects the partially readable database")
            {
                REQUIRE_FALSE(reopened.ok);
                REQUIRE(reopened.reason == "unable to hydrate SQLite rows");
            }
        }

        std::filesystem::remove(sqlite_path);
    }
}

SCENARIO("Persistent store matches state event JSON with whitespace and upserts current state",
         "[database][persistence][review]")
{
    GIVEN("state events with equivalent formatted JSON")
    {
        auto opened = merovingian::database::open_persistent_store();
        REQUIRE(opened.ok);
        auto& store = opened.store;
        // AUTH-11: the store keeps no committed statements unless capture is enabled.
        merovingian::database::enable_statement_capture(store, 256U);
        auto const first_event =
            merovingian::database::store_event(store, {"$event1:example.org", "!room:example.org", "@alice:example.org",
                                                       R"({ "type" : "m.room.topic" , "state_key" : "" })"});
        auto const second_event =
            merovingian::database::store_event(store, {"$event2:example.org", "!room:example.org", "@alice:example.org",
                                                       R"({ "type" : "m.room.topic" , "state_key" : "" })"});
        REQUIRE(first_event);
        REQUIRE(second_event);

        WHEN("the same current-state key is stored twice")
        {
            auto const first_state = merovingian::database::store_state(
                store, {"!room:example.org", "m.room.topic", "", "$event1:example.org"});
            auto const second_state = merovingian::database::store_state(
                store, {"!room:example.org", "m.room.topic", "", "$event2:example.org"});

            THEN("formatted JSON is accepted and the current-state row is replaced")
            {
                REQUIRE(first_state);
                REQUIRE(second_state);
                REQUIRE(store.state.size() == 1U);
                REQUIRE(store.state.front().event_id == "$event2:example.org");
                REQUIRE(store.state_transitions.size() == 2U);
                // The final statement records the second state transition; the
                // current_state row is updated via the preceding upsert_state.
                // ADR-0064 phase B1: this is now an upsert (ON CONFLICT DO
                // UPDATE), not a bare insert — state_transitions' primary key
                // is (room_id, event_type, state_key, event_id), and state
                // resolution can make an event current again after it was
                // previously superseded, which a bare INSERT would reject as
                // a duplicate row on the second occurrence.
                REQUIRE(store.captured_statements.back().name == "upsert_state_transition");
            }
        }
    }
}

SCENARIO("prepare_store_event_with_state derives previous_event_id from the event graph",
         "[database][persistence][state-transitions]")
{
    GIVEN("a room with a chain of m.room.topic state events")
    {
        auto opened = merovingian::database::open_persistent_store();
        REQUIRE(opened.ok);
        auto& store = opened.store;

        auto const room_stored = merovingian::database::store_room_with_membership(
            store, {"!room:example.org", "@alice:example.org"}, {"!room:example.org", "@alice:example.org"});
        REQUIRE(room_stored);

        auto create_event = merovingian::database::PersistentEvent{"$create:example.org",
                                                                   "!room:example.org",
                                                                   "@alice:example.org",
                                                                   R"({"type":"m.room.create","state_key":""})",
                                                                   0U,
                                                                   1U};
        auto const create_stored = merovingian::database::store_event_with_state(
            store, std::move(create_event),
            merovingian::database::PersistentStateEvent{"!room:example.org", "m.room.create", "",
                                                        "$create:example.org"});
        REQUIRE(create_stored);

        auto first_topic = merovingian::database::PersistentEvent{"$topic1:example.org",
                                                                  "!room:example.org",
                                                                  "@alice:example.org",
                                                                  R"({"type":"m.room.topic","state_key":""})",
                                                                  1U,
                                                                  2U,
                                                                  std::vector<std::string>{"$create:example.org"}};
        auto const first_stored = merovingian::database::store_event_with_state(
            store, std::move(first_topic),
            merovingian::database::PersistentStateEvent{"!room:example.org", "m.room.topic", "",
                                                        "$topic1:example.org"});
        REQUIRE(first_stored);

        WHEN("a second topic event names the first as its prev_event")
        {
            auto second_topic = merovingian::database::PersistentEvent{"$topic2:example.org",
                                                                       "!room:example.org",
                                                                       "@alice:example.org",
                                                                       R"({"type":"m.room.topic","state_key":""})",
                                                                       2U,
                                                                       3U,
                                                                       std::vector<std::string>{"$topic1:example.org"}};
            auto const second_stored = merovingian::database::store_event_with_state(
                store, std::move(second_topic),
                merovingian::database::PersistentStateEvent{"!room:example.org", "m.room.topic", "",
                                                            "$topic2:example.org"});

            THEN("the transition records the first topic event as the predecessor")
            {
                REQUIRE(second_stored);
                REQUIRE(store.state_transitions.size() == 3U);
                auto const* transition = merovingian::database::find_state_transition(
                    store, "!room:example.org", "m.room.topic", "", "$topic2:example.org");
                REQUIRE(transition != nullptr);
                REQUIRE(transition->previous_event_id == "$topic1:example.org");
            }
        }
    }
}

// DB-2 (2026-09-29 audit): the SQLite room-snapshot loader used `event_id IN`
// with one placeholder per loaded event. SQLite's default parameter limit is
// 999, but some builds and test fixtures failed at far smaller counts, and
// the query plan degraded with room size. The relation-table reads must scope
// by room_id through a JOIN instead.
SCENARIO("SQLite room snapshot loads event relations with a room-scoped JOIN", "[database][sqlite][security][db-2]")
{
    GIVEN("a SQLite store holding a room with more than 128 events")
    {
        auto const sqlite_path = unique_sqlite_path("room_snapshot_join");
        std::filesystem::remove(sqlite_path);
        auto opened = merovingian::database::open_sqlite_persistent_store(sqlite_path.string());
        if (!opened.ok)
        {
            FAIL(std::string{"open_sqlite_persistent_store failed: "} + opened.reason);
        }
        auto& store = opened.store;

        auto constexpr room_id = "!snapshot:example.org";
        auto constexpr user_id = "@alice:example.org";
        REQUIRE(merovingian::database::store_user(store,
                                                  {std::string{user_id}, "password-hash:v1:1", false, false, false}));
        REQUIRE(merovingian::database::store_room(store, {std::string{room_id}, std::string{user_id}, false}));

        auto constexpr event_count = std::size_t{200U};
        for (auto i = std::size_t{0U}; i < event_count; ++i)
        {
            auto event_id = std::string{"$event-"} + std::to_string(i) + ":example.org";
            auto prev_event_id =
                std::string{"$event-"} + std::to_string((i + event_count - 1U) % event_count) + ":example.org";
            auto event = merovingian::database::PersistentEvent{
                event_id, std::string{room_id},          std::string{user_id},
                "{}",     static_cast<std::uint64_t>(i), static_cast<std::uint64_t>(i)};
            event.status = "normal";
            event.prev_event_ids = {prev_event_id};
            event.auth_event_ids = {"$auth:example.org"};
            event.signatures = {
                {"example.org", "ed25519:test", "fake-signature"}
            };
            REQUIRE(merovingian::database::store_event(store, std::move(event)));
        }

        WHEN("the room snapshot is reloaded")
        {
            REQUIRE(merovingian::database::reload_room(store, room_id));

            THEN("every event still has its prev edges, auth events and signatures reconstructed")
            {
                auto event_with_prev = std::size_t{0U};
                auto event_with_auth = std::size_t{0U};
                auto event_with_signature = std::size_t{0U};
                for (auto const& event : store.events)
                {
                    if (event.room_id != room_id)
                    {
                        continue;
                    }
                    if (!event.prev_event_ids.empty())
                    {
                        ++event_with_prev;
                    }
                    if (!event.auth_event_ids.empty())
                    {
                        ++event_with_auth;
                    }
                    if (!event.signatures.empty())
                    {
                        ++event_with_signature;
                    }
                }
                REQUIRE(event_with_prev == event_count);
                REQUIRE(event_with_auth == event_count);
                REQUIRE(event_with_signature == event_count);
            }
        }

        std::filesystem::remove(sqlite_path);
    }
}
