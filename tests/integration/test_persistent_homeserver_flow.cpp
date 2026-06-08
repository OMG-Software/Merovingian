// SPDX-License-Identifier: GPL-3.0-or-later

#include "../federation_signing_test_support.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/database/migration.hpp"
#include "merovingian/database/schema.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/room_service.hpp"
#include "merovingian/homeserver/runtime.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <string>

namespace
{

[[nodiscard]] auto registration_enabled_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    merovingian::tests::enable_token_registration(security);
    return {
        merovingian::config::ServerConfig{},           merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},         security,
        merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto sqlite_registration_enabled_config(std::filesystem::path const& sqlite_path)
    -> merovingian::config::Config
{
    auto database = merovingian::config::DatabaseConfig{};
    database.backend = merovingian::config::DatabaseBackend::sqlite;
    database.sqlite_path = sqlite_path.string();

    auto security = merovingian::config::SecurityConfig{};
    merovingian::tests::enable_token_registration(security);

    return {
        merovingian::config::ServerConfig{},           merovingian::config::ListenersConfig{},  database, security,
        merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
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
                    runtime,
                    {"POST",
                     "/_matrix/client/v3/register",
                     {},
                     R"({"username":"restart","password":"CorrectHorse7!","auth":{"type":"m.login.registration_token","token":"test-registration-token"}})"});
                auto const login = merovingian::homeserver::handle_client_server_request(
                    runtime,
                    {"POST",
                     "/_matrix/client/v3/login",
                     {},
                     R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@restart:example.org"},"password":"CorrectHorse7!","device_id":"RESTART1"})"});
                token = token_from_login_body(login.response.body);
                auto const room = merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST", "/_matrix/client/v3/createRoom", token, {}});
                room_id = room_from_body(room.response.body);
                auto const send = merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/send", token,
                              R"({"type":"m.room.message","body":"persisted"})"});

                REQUIRE(registered.response.status == 200U);
                REQUIRE(login.response.status == 200U);
                REQUIRE(room.response.status == 200U);
                REQUIRE(send.response.status == 200U);
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
                REQUIRE(whoami.response.status == 200U);
                REQUIRE(whoami.response.body.find(R"("@restart:example.org")") != std::string::npos);
                REQUIRE(state.response.status == 200U);
                REQUIRE(state.response.body.find("m.room.create") != std::string::npos);
                REQUIRE(restarted_runtime.homeserver.database.persistent_store.users.size() == 1U);
                // Register creates one token (alice_DEVICE); login creates a second (RESTART1).
                REQUIRE(restarted_runtime.homeserver.database.persistent_store.access_tokens.size() == 2U);
                REQUIRE(restarted_runtime.homeserver.database.persistent_store.rooms.size() == 1U);
                // createRoom now persists the full preset chain, including
                // guest_access and m.room.encryption (for private_chat preset),
                // before the additional message event is sent.
                REQUIRE(restarted_runtime.homeserver.database.persistent_store.events.size() == 8U);
            }
        }

        std::filesystem::remove(sqlite_path);
    }
}

SCENARIO("SQLite-backed client-server runtime persists E2EE key API state across restart",
         "[database][sqlite][homeserver][key-api][integration]")
{
    GIVEN("a registration-enabled SQLite homeserver config")
    {
        auto const sqlite_path = unique_sqlite_path();
        std::filesystem::remove(sqlite_path);
        auto const config = sqlite_registration_enabled_config(sqlite_path);

        WHEN("a device uploads device, one-time, and fallback keys before restart")
        {
            auto token = std::string{};
            {
                auto started = merovingian::homeserver::start_client_server(config);
                REQUIRE(started.started);
                auto& runtime = started.runtime;

                auto const registered = merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("keys", "CorrectHorse7!")});
                auto const login = merovingian::homeserver::handle_client_server_request(
                    runtime,
                    {"POST",
                     "/_matrix/client/v3/login",
                     {},
                     R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@keys:example.org"},"password":"CorrectHorse7!","device_id":"KEYS1"})"});
                token = token_from_login_body(login.response.body);
                // Real Ed25519 keypair required: OTK and fallback signatures
                // are now cryptographically verified server-side.
                auto const keys_kp =
                    merovingian::federation::test::keypair_from_seed("persistent-keys-seed");
                auto const keys_ed25519 = merovingian::federation::test::pubkey_b64(keys_kp);
                auto const otk_json = merovingian::federation::test::make_signed_otk_json(
                    "@keys:example.org", "KEYS1", "otk", keys_kp.secret_key);
                auto const fb_json = merovingian::federation::test::make_signed_fallback_key_json(
                    "@keys:example.org", "KEYS1", "fallback", keys_kp.secret_key);
                auto const keys_upload_body =
                    std::string{
                        R"({"device_keys":{"algorithms":["m.olm.v1.curve25519-aes-sha2","m.megolm.v1.aes-sha2"],"device_id":"KEYS1","keys":{"curve25519:KEYS1":"curve-key","ed25519:KEYS1":")"} +
                    keys_ed25519 +
                    R"("},"signatures":{},"user_id":"@keys:example.org"},"one_time_keys":{"signed_curve25519:AAA":)" +
                    otk_json +
                    R"(},"fallback_keys":{"signed_curve25519:FB":)" + fb_json + R"(}})";
                auto const upload = merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST", "/_matrix/client/v3/keys/upload", token, keys_upload_body});

                REQUIRE(registered.response.status == 200U);
                REQUIRE(login.response.status == 200U);
                REQUIRE(upload.response.status == 200U);
                REQUIRE(std::filesystem::exists(sqlite_path));
            }

            auto restarted = merovingian::homeserver::start_client_server(config);
            REQUIRE(restarted.started);
            auto& runtime = restarted.runtime;
            auto const query = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST", "/_matrix/client/v3/keys/query", token, R"({"device_keys":{"@keys:example.org":["KEYS1"]}})"});
            auto const first_claim = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/keys/claim", token,
                          R"({"one_time_keys":{"@keys:example.org":{"KEYS1":"signed_curve25519"}}})"});
            auto const second_claim = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/keys/claim", token,
                          R"({"one_time_keys":{"@keys:example.org":{"KEYS1":"signed_curve25519"}}})"});

            THEN("device keys survive restart and fallback keys are reused after one-time keys are consumed")
            {
                REQUIRE(query.response.status == 200U);
                REQUIRE(first_claim.response.status == 200U);
                REQUIRE(second_claim.response.status == 200U);
                REQUIRE(query.response.body.find("m.megolm.v1.aes-sha2") != std::string::npos);
                REQUIRE(first_claim.response.body.find("otk") != std::string::npos);
                REQUIRE(second_claim.response.body.find("fallback") != std::string::npos);
                REQUIRE(runtime.homeserver.database.persistent_store.device_keys.size() == 1U);
                REQUIRE(runtime.homeserver.database.persistent_store.one_time_keys.empty());
                REQUIRE(runtime.homeserver.database.persistent_store.fallback_keys.size() == 1U);
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
                REQUIRE(merovingian::homeserver::database_has_table(started.runtime.database, "device_keys"));
                REQUIRE(merovingian::homeserver::database_has_table(started.runtime.database, "key_backup_sessions"));
                REQUIRE(merovingian::homeserver::database_has_table(started.runtime.database, "admin_actions"));
                REQUIRE(started.runtime.database.persistent_store.schema.applied_migrations.size() == 1U);
                REQUIRE(started.runtime.database.persistent_store.schema.applied_migrations.front().direction ==
                        merovingian::database::MigrationDirection::upgrade);
                REQUIRE(started.runtime.database.persistent_store.schema.applied_migrations.front().name ==
                        "initial_schema");
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
                REQUIRE(started.runtime.database.persistent_store.schema.applied_migrations.size() == 1U);
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
                runtime, {"POST",
                          "/_matrix/client/v3/register",
                          {},
                          merovingian::tests::registration_json("alice", "CorrectHorse7!")});
            auto const login = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST",
                 "/_matrix/client/v3/login",
                 {},
                 R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
            auto const token = token_from_login_body(login.response.body);
            auto const room = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/createRoom", token, {}});
            auto const room_id = room_from_body(room.response.body);
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
                REQUIRE(registered.response.status == 200U);
                REQUIRE(login.response.status == 200U);
                REQUIRE(room.response.status == 200U);
                REQUIRE(send.response.status == 200U);
                REQUIRE(state.response.status == 200U);
                REQUIRE(logout.response.status == 200U);
                REQUIRE(valid_store.valid);
                REQUIRE(runtime.homeserver.database.persistent_store.users.size() == 1U);
                // Spec §5.5.1: /register creates one device (alice_DEVICE) when
                // inhibit_login is absent. /login creates a second device (DEVICE1).
                REQUIRE(runtime.homeserver.database.persistent_store.devices.size() == 2U);
                // Two access tokens: one from the implicit registration session and
                // one from the explicit /login. /logout revokes the login token only.
                auto const& all_tokens = runtime.homeserver.database.persistent_store.access_tokens;
                REQUIRE(all_tokens.size() == 2U);
                // Exactly one token must be revoked (the one used for /logout).
                auto const revoked = std::count_if(all_tokens.begin(), all_tokens.end(), [](auto const& t) {
                    return t.revoked;
                });
                REQUIRE(revoked == 1U);
                // Both tokens must use the v2 hash format.
                auto const all_v2 = std::all_of(all_tokens.begin(), all_tokens.end(), [](auto const& t) {
                    return t.token_hash.find("token-hash:v2:") == 0U;
                });
                REQUIRE(all_v2);
                REQUIRE(runtime.homeserver.database.persistent_store.rooms.size() == 1U);
                REQUIRE(runtime.homeserver.database.persistent_store.memberships.size() == 1U);
                REQUIRE(runtime.homeserver.database.persistent_store.events.size() == 8U);
                REQUIRE(runtime.homeserver.database.persistent_store.state.size() == 7U);
                REQUIRE(runtime.homeserver.database.persistent_store.audit_log.size() >= 6U);
                REQUIRE(
                    merovingian::database::sensitive_values_are_redacted(runtime.homeserver.database.persistent_store));
            }
        }
    }
}
