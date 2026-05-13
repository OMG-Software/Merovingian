// SPDX-License-Identifier: GPL-3.0-or-later

#include <chrono>
#include <filesystem>
#include <string>

#include <catch2/catch_test_macros.hpp>
#include "merovingian/config/config.hpp"
#include "merovingian/database/migration.hpp"
#include "merovingian/database/schema.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/vertical_slice.hpp"

namespace
{

[[nodiscard]] auto registration_enabled_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.registration.enabled = true;
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},
        security,
    };
}

[[nodiscard]] auto sqlite_registration_enabled_config(std::filesystem::path const& sqlite_path)
    -> merovingian::config::Config
{
    auto database = merovingian::config::DatabaseConfig{};
    database.backend = merovingian::config::DatabaseBackend::sqlite;
    database.sqlite_path = sqlite_path.string();

    auto security = merovingian::config::SecurityConfig{};
    security.registration.enabled = true;

    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        database,
        security,
    };
}

[[nodiscard]] auto token_from_login_body(std::string const& body) -> std::string
{
    auto const key = std::string{"\"access_token\":\""};
    auto const begin = body.find(key);
    REQUIRE(begin != std::string::npos);
    auto const value_begin = begin + key.size();
    auto const value_end = body.find('"', value_begin);
    REQUIRE(value_end != std::string::npos);
    return body.substr(value_begin, value_end - value_begin);
}

[[nodiscard]] auto room_from_body(std::string const& body) -> std::string
{
    auto const key = std::string{"\"room_id\":\""};
    auto const begin = body.find(key);
    REQUIRE(begin != std::string::npos);
    auto const value_begin = begin + key.size();
    auto const value_end = body.find('"', value_begin);
    REQUIRE(value_end != std::string::npos);
    return body.substr(value_begin, value_end - value_begin);
}

[[nodiscard]] auto unique_sqlite_path() -> std::filesystem::path
{
    auto const now = std::chrono::steady_clock::now().time_since_epoch().count();
    return std::filesystem::temp_directory_path() / ("merovingian-restart-flow-" + std::to_string(now) + ".sqlite3");
}

} // namespace

SCENARIO("SQLite-backed homeserver runtime survives restart with users sessions rooms and events",
         "[database][sqlite][homeserver][integration]")
{
    GIVEN("a registration-enabled SQLite homeserver config")
    {
        auto const sqlite_path = unique_sqlite_path();
        std::filesystem::remove(sqlite_path);
        auto const config = sqlite_registration_enabled_config(sqlite_path);

        WHEN("a user creates a room and the runtime is started again from the same SQLite file")
        {
            auto token = std::string{};
            auto room_id = std::string{};
            {
                auto started = merovingian::homeserver::start_client_server(config);
                REQUIRE(started.started);
                auto& runtime = started.runtime;

                auto const registered = merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              R"({"username":"restart","password":"CorrectHorse7!"})"});
                auto const login = merovingian::homeserver::handle_client_server_request(
                    runtime,
                    {"POST",
                     "/_matrix/client/v3/login",
                     {},
                     R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@restart:example.org"},"password":"CorrectHorse7!","device_id":"RESTART1"})"});
                token = token_from_login_body(login.body);
                auto const room = merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST", "/_matrix/client/v3/createRoom", token, {}});
                room_id = room_from_body(room.body);
                auto const send = merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/send", token,
                              R"({"type":"m.room.message","body":"persisted"})"});

                REQUIRE(registered.status == 200U);
                REQUIRE(login.status == 200U);
                REQUIRE(room.status == 200U);
                REQUIRE(send.status == 200U);
                REQUIRE(std::filesystem::exists(sqlite_path));
            }

            auto restarted = merovingian::homeserver::start_client_server(config);
            REQUIRE(restarted.started);
            auto& restarted_runtime = restarted.runtime;
            auto const whoami = merovingian::homeserver::handle_client_server_request(
                restarted_runtime, {"GET", "/_matrix/client/v3/account/whoami", token, {}});
            auto const state = merovingian::homeserver::handle_client_server_request(
                restarted_runtime, {"GET", "/_matrix/client/v3/rooms/" + room_id + "/state", token, {}});

            THEN("the restarted runtime authenticates the old token and exposes the persisted room state")
            {
                REQUIRE(whoami.status == 200U);
                REQUIRE(whoami.body.find(R"("@restart:example.org")") != std::string::npos);
                REQUIRE(state.status == 200U);
                REQUIRE(state.body.find("events=1") != std::string::npos);
                REQUIRE(restarted_runtime.homeserver.database.persistent_store.users.size() == 1U);
                REQUIRE(restarted_runtime.homeserver.database.persistent_store.access_tokens.size() == 1U);
                REQUIRE(restarted_runtime.homeserver.database.persistent_store.rooms.size() == 1U);
                REQUIRE(restarted_runtime.homeserver.database.persistent_store.events.size() == 1U);
            }
        }

        std::filesystem::remove(sqlite_path);
    }
}

SCENARIO("Persistent homeserver runtime bootstraps a fresh migrated schema", "[database][homeserver][integration]")
{
    GIVEN("registration-enabled config and no existing schema")
    {
        auto const config = registration_enabled_config();

        WHEN("the runtime starts")
        {
            auto const started = merovingian::homeserver::start_runtime(config);

            THEN("startup applies the current migration and validates required tables")
            {
                REQUIRE(started.started);
                REQUIRE(started.runtime.database.opened);
                REQUIRE(started.runtime.database.schema_validated);
                REQUIRE(started.runtime.database.schema_version == merovingian::database::current_schema_version());
                REQUIRE(merovingian::homeserver::database_has_table(started.runtime.database, "schema_migrations"));
                REQUIRE(merovingian::homeserver::database_has_table(started.runtime.database, "access_tokens"));
                REQUIRE(merovingian::homeserver::database_has_table(started.runtime.database, "membership"));
                REQUIRE(merovingian::homeserver::database_has_table(started.runtime.database, "current_state"));
                REQUIRE(merovingian::homeserver::database_has_table(started.runtime.database, "admin_actions"));
                REQUIRE(started.runtime.database.persistent_store.schema.applied_migrations.size() == 2U);
                REQUIRE(started.runtime.database.persistent_store.schema.applied_migrations.front().direction ==
                        merovingian::database::MigrationDirection::upgrade);
                REQUIRE(started.runtime.database.persistent_store.schema.applied_migrations.back().name ==
                        "media_metadata_columns");
            }
        }
    }
}

SCENARIO("Persistent homeserver startup is idempotent for an already migrated schema",
         "[database][homeserver][integration]")
{
    GIVEN("an already migrated schema state")
    {
        auto const first = merovingian::database::open_persistent_store();
        REQUIRE(first.ok);

        WHEN("the runtime starts with that state")
        {
            auto const started =
                merovingian::homeserver::start_runtime(registration_enabled_config(), first.store.schema);

            THEN("startup validates compatibility without applying duplicate migrations")
            {
                REQUIRE(started.started);
                REQUIRE(started.runtime.database.persistent_store.schema.version ==
                        merovingian::database::current_schema_version());
                REQUIRE(started.runtime.database.persistent_store.schema.applied_migrations.size() == 2U);
            }
        }
    }
}

SCENARIO("Persistent homeserver startup fails closed on schema mismatch", "[database][homeserver][integration]")
{
    GIVEN("a future incompatible schema state")
    {
        auto opened = merovingian::database::open_persistent_store();
        REQUIRE(opened.ok);
        auto future = opened.store.schema;
        future.version = merovingian::database::current_schema_version() + 1U;

        WHEN("the runtime starts")
        {
            auto const started = merovingian::homeserver::start_runtime(registration_enabled_config(), future);

            THEN("the runtime rejects traffic before serving")
            {
                REQUIRE_FALSE(started.started);
                REQUIRE(started.reason == "database schema validation failed");
            }
        }
    }
}

SCENARIO("Persistent homeserver store records the client-server flow",
         "[database][homeserver][client-server][integration]")
{
    GIVEN("a started client-server runtime")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("a user registers logs in creates a room sends a message and logs out")
        {
            auto const registered = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST", "/_matrix/client/v3/register", {}, R"({"username":"alice","password":"CorrectHorse7!"})"});
            auto const login = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST",
                 "/_matrix/client/v3/login",
                 {},
                 R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
            auto const token = token_from_login_body(login.body);
            auto const room = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/createRoom", token, {}});
            auto const room_id = room_from_body(room.body);
            auto const send = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST", "/_matrix/client/v3/rooms/" + room_id + "/send", token, R"({"type":"m.room.message"})"});
            auto const state = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/rooms/" + room_id + "/state", token, {}});
            auto const logout = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/logout", token, {}});
            auto const valid_store =
                merovingian::database::validate_persistent_store(runtime.homeserver.database.persistent_store);

            THEN("message events are durable without synthetic current-state rows")
            {
                REQUIRE(registered.status == 200U);
                REQUIRE(login.status == 200U);
                REQUIRE(room.status == 200U);
                REQUIRE(send.status == 200U);
                REQUIRE(state.status == 200U);
                REQUIRE(logout.status == 200U);
                REQUIRE(valid_store.valid);
                REQUIRE(runtime.homeserver.database.persistent_store.users.size() == 1U);
                REQUIRE(runtime.homeserver.database.persistent_store.devices.size() == 1U);
                REQUIRE(runtime.homeserver.database.persistent_store.access_tokens.size() == 1U);
                REQUIRE(runtime.homeserver.database.persistent_store.access_tokens.front().token_hash.find(
                            "token-hash:v2:") == 0U);
                REQUIRE(runtime.homeserver.database.persistent_store.access_tokens.front().revoked);
                REQUIRE(runtime.homeserver.database.persistent_store.rooms.size() == 1U);
                REQUIRE(runtime.homeserver.database.persistent_store.memberships.size() == 1U);
                REQUIRE(runtime.homeserver.database.persistent_store.events.size() == 1U);
                REQUIRE(runtime.homeserver.database.persistent_store.state.empty());
                REQUIRE(runtime.homeserver.database.persistent_store.audit_log.size() >= 6U);
                REQUIRE(
                    merovingian::database::sensitive_values_are_redacted(runtime.homeserver.database.persistent_store));
            }
        }
    }
}
