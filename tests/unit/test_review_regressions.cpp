// SPDX-License-Identifier: GPL-3.0-or-later

#include "../support/registration_token.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/database/migration.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/database/schema.hpp"
#include "merovingian/homeserver/http_server.hpp"
#include "merovingian/homeserver/vertical_slice.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include <sqlite3.h>

namespace
{

class TestSqliteConnection final
{
public:
    explicit TestSqliteConnection(std::filesystem::path const& path)
    {
        static_cast<void>(sqlite3_open(path.string().c_str(), &connection_));
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

[[nodiscard]] auto registration_enabled_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    merovingian::tests::enable_token_registration(security);
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},
        security,
    };
}

[[nodiscard]] auto token_required_registration_config(std::filesystem::path const& token_file)
    -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.registration.enabled = true;
    security.registration.require_token = true;
    security.registration.token_file = token_file.string();
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},
        security,
    };
}

[[nodiscard]] auto unique_secret_path(std::string const& suffix) -> std::filesystem::path
{
    auto const now = std::chrono::steady_clock::now().time_since_epoch().count();
    return std::filesystem::temp_directory_path() / ("merovingian-secret-" + suffix + "-" + std::to_string(now));
}

[[nodiscard]] auto unique_sqlite_path(std::string const& suffix) -> std::filesystem::path
{
    auto const now = std::chrono::steady_clock::now().time_since_epoch().count();
    return std::filesystem::temp_directory_path() /
           ("merovingian-review-" + suffix + "-" + std::to_string(now) + ".sqlite3");
}

} // namespace

SCENARIO("Admin health remains admin-only after router split", "[homeserver][security][review]")
{
    GIVEN("a runtime with an admin user and a regular user")
    {
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const admin_user = merovingian::homeserver::bootstrap_admin_user(runtime, "alice", "CorrectHorse7!");
        auto const admin_login =
            merovingian::homeserver::login_local_user(runtime, admin_user.value, "CorrectHorse7!", "ADMIN1");
        auto const normal_user = merovingian::homeserver::register_local_user(runtime, "bob", "CorrectHorse8!",
                                                                              merovingian::tests::registration_token);
        auto const normal_login =
            merovingian::homeserver::login_local_user(runtime, normal_user.value, "CorrectHorse8!", "USER1");
        REQUIRE(admin_login.ok);
        REQUIRE(normal_login.ok);

        WHEN("both users request admin health")
        {
            auto const admin_response = merovingian::homeserver::handle_local_http_request(
                runtime, {"GET", "/_merovingian/admin/health", admin_login.value, {}});
            auto const normal_response = merovingian::homeserver::handle_local_http_request(
                runtime, {"GET", "/_merovingian/admin/health", normal_login.value, {}});

            THEN("only the admin session can read operational health")
            {
                REQUIRE(admin_response.status == 200U);
                REQUIRE(normal_response.status == 401U);
                REQUIRE_FALSE(
                    merovingian::homeserver::authenticated_admin_user(runtime, normal_login.value).has_value());
            }
        }
    }
}

SCENARIO("Public registration enforces configured token policy and never bootstraps admin",
         "[homeserver][security][auth][review]")
{
    GIVEN("a runtime with token-protected registration")
    {
        auto const token_file = unique_secret_path("registration-token");
        {
            auto output = std::ofstream{token_file};
            output << "register-alpha-token\n";
        }
        auto started = merovingian::homeserver::start_client_server(token_required_registration_config(token_file));
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("clients register without, with invalid, and with valid registration tokens")
        {
            auto const missing_token = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST", "/_matrix/client/v3/register", {}, R"({"username":"alice","password":"CorrectHorse7!"})"});
            auto const invalid_token = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST",
                 "/_matrix/client/v3/register",
                 {},
                 R"({"auth":{"type":"m.login.registration_token","token":"wrong"},"username":"alice","password":"CorrectHorse7!"})"});
            auto const accepted = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST",
                 "/_matrix/client/v3/register",
                 {},
                 R"({"auth":{"type":"m.login.registration_token","token":"register-alpha-token"},"username":"alice","password":"CorrectHorse7!"})"});

            THEN("only the valid token creates a non-admin user")
            {
                // No auth field yields the UI-auth challenge (401); a present
                // but invalid token is rejected outright (403).
                REQUIRE(missing_token.status == 401U);
                REQUIRE(invalid_token.status == 403U);
                REQUIRE(accepted.status == 200U);
                REQUIRE_FALSE(runtime.homeserver.database.users.empty());
                REQUIRE_FALSE(runtime.homeserver.database.users.front().admin);
            }
        }

        std::filesystem::remove(token_file);
    }
}

SCENARIO("Federation dispatch exposes only federation routes", "[homeserver][security][federation][review]")
{
    GIVEN("a started runtime served through federation dispatch mode")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("admin, client, and federation key routes are requested")
        {
            auto const admin = merovingian::homeserver::dispatch_local_http_request(
                runtime, {"GET", "/_merovingian/admin/health", {}, {}},
                merovingian::homeserver::HttpDispatchMode::federation);
            auto const client_register = merovingian::homeserver::dispatch_local_http_request(
                runtime,
                {"POST",
                 "/_matrix/client/v3/register",
                 {},
                 merovingian::tests::registration_pipe("alice", "CorrectHorse7!")},
                merovingian::homeserver::HttpDispatchMode::federation);
            auto const keys = merovingian::homeserver::dispatch_local_http_request(
                runtime, {"GET", "/_matrix/key/v2/server", {}, {}},
                merovingian::homeserver::HttpDispatchMode::federation);

            THEN("non-federation surfaces are hidden and federation keys remain reachable")
            {
                REQUIRE(admin.status == 404U);
                REQUIRE(client_register.status == 404U);
                REQUIRE(keys.status == 200U);
                REQUIRE(keys.body.find("\"verify_keys\"") != std::string::npos);
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
        auto const upgraded =
            merovingian::database::apply_migration_plan({}, merovingian::database::migration_plan_between(0U, 1U));
        REQUIRE(upgraded.ok);
        auto const downgraded = merovingian::database::apply_migration_plan(
            upgraded.state, merovingian::database::migration_plan_between(1U, 0U));
        REQUIRE(downgraded.ok);

        WHEN("the schema is upgraded again")
        {
            auto const reapplied = merovingian::database::apply_migration_plan(
                downgraded.state, merovingian::database::migration_plan_between(0U, 1U));

            THEN("tables are recreated even though migration history still contains the old upgrade record")
            {
                REQUIRE(reapplied.ok);
                REQUIRE(reapplied.state.version == 1U);
                REQUIRE(reapplied.state.tables.size() == merovingian::database::initial_schema_tables().size());
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
                REQUIRE(store.prepared_statements.size() == 2U);
                REQUIRE(store.prepared_statements[0].name == "insert_user");
                REQUIRE(store.prepared_statements[1].name == "insert_device");
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

        WHEN("the same token hash is stored twice")
        {
            auto const first = merovingian::database::store_access_token(
                store, {"@alice:example.org", "DEVICE1", "token-hash:v2:abc", false});
            auto const duplicate = merovingian::database::store_access_token(
                store, {"@alice:example.org", "DEVICE1", "token-hash:v2:abc", false});

            THEN("only one token row and statement are recorded")
            {
                REQUIRE(first);
                REQUIRE_FALSE(duplicate);
                REQUIRE(store.access_tokens.size() == 1U);
                REQUIRE(store.prepared_statements.size() == 1U);
                REQUIRE(store.prepared_statements.front().name == "insert_access_token");
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

        WHEN("a login transaction is attempted with an invalid token hash")
        {
            auto const rejected = merovingian::database::store_device_and_access_token(
                store, merovingian::database::PersistentDevice{"@alice:example.org", "DEVICE1", "Alice laptop"},
                {"@alice:example.org", "DEVICE1", "plaintext", false});

            THEN("neither durable side effect is recorded")
            {
                REQUIRE_FALSE(rejected);
                REQUIRE(store.devices.empty());
                REQUIRE(store.access_tokens.empty());
                REQUIRE(store.prepared_statements.empty());
            }
        }

        WHEN("a login transaction has a new device and hashed token")
        {
            auto const stored = merovingian::database::store_device_and_access_token(
                store, merovingian::database::PersistentDevice{"@alice:example.org", "DEVICE1", "Alice laptop"},
                {"@alice:example.org", "DEVICE1", "token-hash:v2:abc", false});

            THEN("the device and access token become visible together")
            {
                REQUIRE(stored);
                REQUIRE(store.devices.size() == 1U);
                REQUIRE(store.access_tokens.size() == 1U);
                REQUIRE(store.prepared_statements.size() == 2U);
                REQUIRE(store.prepared_statements[0].name == "insert_device");
                REQUIRE(store.prepared_statements[1].name == "insert_access_token");
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
                REQUIRE(store.prepared_statements.size() == 4U);
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
        auto const statements = std::vector<merovingian::database::PreparedStatement>{
            {"insert_room",
             "INSERT INTO rooms VALUES ($1, $2)", {{"!room1:example.org", false}, {"@alice:example.org", false}}},
            {"insert_room_duplicate",
             "INSERT INTO rooms VALUES ($1, $2)", {{"!room1:example.org", false}, {"@bob:example.org", false}}  },
        };

        WHEN("the transaction is committed")
        {
            auto const committed = merovingian::database::commit_persistent_transaction(store, statements);
            auto reopened = merovingian::database::open_sqlite_persistent_store(sqlite_path.string());
            REQUIRE(reopened.ok);

            THEN("the first insert is rolled back with the failing insert")
            {
                REQUIRE_FALSE(committed);
                REQUIRE(store.prepared_statements.empty());
                REQUIRE(reopened.store.rooms.empty());
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
                REQUIRE(store.prepared_statements.back().name == "upsert_state");
            }
        }
    }
}

SCENARIO("Persisted local event ids are unique across rooms", "[homeserver][rooms][review]")
{
    GIVEN("a logged-in local user with two rooms")
    {
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const user = merovingian::homeserver::register_local_user(runtime, "alice", "CorrectHorse7!",
                                                                       merovingian::tests::registration_token);
        auto const login = merovingian::homeserver::login_local_user(runtime, user.value, "CorrectHorse7!", "DEVICE1");
        auto const first_room = merovingian::homeserver::create_room(runtime, login.value);
        auto const second_room = merovingian::homeserver::create_room(runtime, login.value);
        REQUIRE(first_room.ok);
        REQUIRE(second_room.ok);

        WHEN("one event is sent to each room")
        {
            auto const first_event =
                merovingian::homeserver::send_event(runtime, login.value, first_room.value, "event-one");
            auto const second_event =
                merovingian::homeserver::send_event(runtime, login.value, second_room.value, "event-two");

            THEN("event ids do not collide in persistent storage")
            {
                REQUIRE(first_event.ok);
                REQUIRE(second_event.ok);
                REQUIRE(first_event.value != second_event.value);
                REQUIRE(runtime.database.persistent_store.events.size() == 2U);
                REQUIRE(runtime.database.persistent_store.events[0].event_id !=
                        runtime.database.persistent_store.events[1].event_id);
            }
        }
    }
}

SCENARIO("Sending a state event mirrors current state", "[homeserver][rooms][review]")
{
    GIVEN("a logged-in local user with a room")
    {
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const user = merovingian::homeserver::register_local_user(runtime, "alice", "CorrectHorse7!",
                                                                       merovingian::tests::registration_token);
        auto const login = merovingian::homeserver::login_local_user(runtime, user.value, "CorrectHorse7!", "DEVICE1");
        auto const room = merovingian::homeserver::create_room(runtime, login.value);
        REQUIRE(room.ok);

        WHEN("a room state event is sent")
        {
            auto const event = merovingian::homeserver::send_event(runtime, login.value, room.value,
                                                                   R"({ "type" : "m.room.topic" , "state_key" : "" })");

            THEN("the event is persisted and materialized as current state")
            {
                REQUIRE(event.ok);
                REQUIRE(runtime.database.persistent_store.events.size() == 1U);
                REQUIRE(runtime.database.persistent_store.state.size() == 1U);
                REQUIRE(runtime.database.persistent_store.state.front().event_type == "m.room.topic");
                REQUIRE(runtime.database.persistent_store.state.front().state_key.empty());
                REQUIRE(runtime.database.persistent_store.state.front().event_id == event.value);
            }
        }
    }
}
