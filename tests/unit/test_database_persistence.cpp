// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/database/connection.hpp"
#include "merovingian/database/migration.hpp"
#include "merovingian/database/migration_files.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/database/postgresql_store.hpp"
#include "merovingian/database/schema.hpp"
#include "merovingian/database/statement.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>
#include <type_traits>
#include <vector>

namespace
{

class RecordingExecutor final : public merovingian::database::DatabaseExecutor
{
public:
    [[nodiscard]] auto execute(merovingian::database::PreparedStatement const& statement)
        -> merovingian::database::QueryResult override
    {
        executed_statement_names_.push_back(statement.name);
        return {true, {}, {{"ok"}}};
    }

    [[nodiscard]] auto executed_statement_names() const noexcept -> std::vector<std::string> const&
    {
        return executed_statement_names_;
    }

private:
    std::vector<std::string> executed_statement_names_{};
};

[[nodiscard]] auto create_users_statement() -> merovingian::database::PreparedStatement
{
    return {"create_users", "CREATE TABLE users (user_id TEXT PRIMARY KEY)", {}};
}

[[nodiscard]] auto unique_sqlite_path() -> std::filesystem::path
{
    auto const now = std::chrono::steady_clock::now().time_since_epoch().count();
    return std::filesystem::temp_directory_path() /
           ("merovingian-transaction-unit-" + std::to_string(now) + ".sqlite3");
}

} // namespace

SCENARIO("Database statement validation enforces prepared statement shape", "[database]")
{
    GIVEN("valid and invalid prepared statements")
    {
        auto const valid_statement = merovingian::database::PreparedStatement{
            "select_user_by_id",
            "SELECT id FROM users WHERE id = $1",
            {merovingian::database::BoundValue{"@alice:example.org", false}},
        };
        auto const invalid_name =
            merovingian::database::PreparedStatement{"select-user", "SELECT id FROM users WHERE id = $1", {}};
        auto const unsafe_sql =
            merovingian::database::PreparedStatement{"select_user", "SELECT id FROM users; SELECT id FROM devices", {}};

        WHEN("the statements are validated")
        {
            auto const valid_result = merovingian::database::prepared_statement_is_valid(valid_statement);
            auto const invalid_name_result = merovingian::database::prepared_statement_is_valid(invalid_name);
            auto const unsafe_sql_result = merovingian::database::prepared_statement_is_valid(unsafe_sql);

            THEN("only the bounded prepared statement shape is accepted")
            {
                REQUIRE(valid_result.valid);
                REQUIRE_FALSE(invalid_name_result.valid);
                REQUIRE(invalid_name_result.reason == "invalid statement name");
                REQUIRE_FALSE(unsafe_sql_result.valid);
                REQUIRE(unsafe_sql_result.reason == "SQL shape is not allowed");
            }
        }
    }
}

SCENARIO("Database statement validation allows SET and RESET role switching SQL", "[database]")
{
    GIVEN("SET ROLE and RESET ROLE statements with no placeholders")
    {
        auto const set_role = merovingian::database::PreparedStatement{
            "set_postgresql_role", R"(SET ROLE "merovingian_runtime")", {}};
        auto const reset_role =
            merovingian::database::PreparedStatement{"reset_postgresql_role", "RESET ROLE", {}};

        WHEN("each statement is validated")
        {
            auto const set_result = merovingian::database::prepared_statement_is_valid(set_role);
            auto const reset_result = merovingian::database::prepared_statement_is_valid(reset_role);

            THEN("the boundary accepts both as legal session-config statements")
            {
                REQUIRE(set_result.valid);
                REQUIRE(reset_result.valid);
            }
        }
    }
}

SCENARIO("Database statement validation enforces placeholder arity", "[database]")
{
    GIVEN("statements with matching and mismatched placeholder arity")
    {
        auto const valid_statement = merovingian::database::PreparedStatement{
            "select_user_device",
            "SELECT id FROM devices WHERE user_id = $1 AND device_id = $2",
            {
              merovingian::database::BoundValue{"@alice:example.org", false},
              merovingian::database::BoundValue{"DEVICE", false},
              },
        };
        auto const missing_first_placeholder = merovingian::database::PreparedStatement{
            "select_device",
            "SELECT id FROM devices WHERE device_id = $2",
            {merovingian::database::BoundValue{"DEVICE", false}},
        };
        auto const extra_parameter = merovingian::database::PreparedStatement{
            "select_users",
            "SELECT id FROM users",
            {merovingian::database::BoundValue{"unused", false}},
        };

        WHEN("the statements are validated")
        {
            auto const valid_result = merovingian::database::prepared_statement_is_valid(valid_statement);
            auto const missing_first_result =
                merovingian::database::prepared_statement_is_valid(missing_first_placeholder);
            auto const extra_parameter_result = merovingian::database::prepared_statement_is_valid(extra_parameter);

            THEN("placeholder indexes must match the bound parameter count exactly")
            {
                REQUIRE(valid_result.valid);
                REQUIRE_FALSE(missing_first_result.valid);
                REQUIRE(missing_first_result.reason == "SQL placeholder arity does not match bound parameters");
                REQUIRE_FALSE(extra_parameter_result.valid);
                REQUIRE(extra_parameter_result.reason == "SQL placeholder arity does not match bound parameters");
            }
        }
    }
}

SCENARIO("Database executor validates statements before execution", "[database]")
{
    GIVEN("a recording executor and valid or invalid statements")
    {
        auto executor = RecordingExecutor{};
        auto const valid_statement =
            merovingian::database::PreparedStatement{"select_user", "SELECT id FROM users", {}};
        auto const invalid_statement =
            merovingian::database::PreparedStatement{"select-user", "SELECT id FROM users", {}};

        WHEN("validated execution is requested")
        {
            auto const valid_result = merovingian::database::execute_validated(executor, valid_statement);
            auto const invalid_result = merovingian::database::execute_validated(executor, invalid_statement);

            THEN("invalid statements fail before reaching the executor")
            {
                REQUIRE(valid_result.ok);
                REQUIRE_FALSE(invalid_result.ok);
                REQUIRE(invalid_result.error == "invalid statement name");
                REQUIRE(executor.executed_statement_names().size() == 1U);
                REQUIRE(executor.executed_statement_names().front() == "select_user");
            }
        }
    }
}

SCENARIO("PostgreSQL executor connection supports RAII moves", "[database][postgresql]")
{
    GIVEN("the PostgreSQL connection owns libpq state through an executor base")
    {
        WHEN("the connection type is returned by value from factory results")
        {
            THEN("the executor base permits moving while still rejecting copies")
            {
                STATIC_REQUIRE(std::is_move_constructible_v<merovingian::database::PostgresqlConnection>);
                STATIC_REQUIRE(std::is_move_assignable_v<merovingian::database::PostgresqlConnection>);
                STATIC_REQUIRE_FALSE(std::is_copy_constructible_v<merovingian::database::PostgresqlConnection>);
                STATIC_REQUIRE_FALSE(std::is_copy_assignable_v<merovingian::database::PostgresqlConnection>);
            }
        }
    }
}

SCENARIO("Database bound value summaries redact sensitive values", "[database]")
{
    GIVEN("public and sensitive bound parameters")
    {
        auto const parameters = std::vector<merovingian::database::BoundValue>{
            {"@alice:example.org", false},
            {"secret-token-hash",  true }
        };

        WHEN("a parameter summary is produced")
        {
            auto const summary = merovingian::database::redacted_parameter_summary(parameters);

            THEN("the sensitive value is not disclosed")
            {
                REQUIRE(summary == "parameters=2 [present, redacted]");
                REQUIRE(summary.find("secret-token-hash") == std::string::npos);
            }
        }
    }
}

SCENARIO("Database migration plans are contiguous and direction-aware", "[database][migration]")
{
    GIVEN("valid, wrong-direction, and non-contiguous migration plans")
    {
        auto const valid_plan = merovingian::database::MigrationPlan{
            0U,
            2U,
            {
              merovingian::database::MigrationStep{1U, "create_users", {create_users_statement()}},
              merovingian::database::MigrationStep{
                    2U,
                    "create_devices",
                    {{"create_devices", "CREATE TABLE devices (device_id TEXT PRIMARY KEY)", {}}}},
              },
            merovingian::database::MigrationDirection::upgrade,
        };
        auto const wrong_direction_plan = merovingian::database::MigrationPlan{
            2U,
            1U,
            {merovingian::database::MigrationStep{1U, "drop_devices", {{"drop_devices", "DROP TABLE devices", {}}}}},
            merovingian::database::MigrationDirection::upgrade};
        auto const gap_plan = merovingian::database::MigrationPlan{
            0U,
            2U,
            {merovingian::database::MigrationStep{
                2U, "create_devices", {{"create_devices", "CREATE TABLE devices (device_id TEXT PRIMARY KEY)", {}}}}}};

        WHEN("the migration plans are validated")
        {
            auto const valid_result = merovingian::database::migration_plan_is_valid(valid_plan);
            auto const wrong_direction_result = merovingian::database::migration_plan_is_valid(wrong_direction_plan);
            auto const gap_result = merovingian::database::migration_plan_is_valid(gap_plan);
            auto const summary = merovingian::database::migration_plan_summary(valid_plan);

            THEN("only contiguous plans with the correct direction are accepted")
            {
                REQUIRE(valid_result.valid);
                REQUIRE_FALSE(wrong_direction_result.valid);
                REQUIRE(wrong_direction_result.reason == "downgrade migration plan has wrong direction");
                REQUIRE_FALSE(gap_result.valid);
                REQUIRE(gap_result.reason == "migration versions must be contiguous");
                REQUIRE(summary == "database migration plan direction=upgrade current_version=0 "
                                   "target_version=2 steps=2");
            }
        }
    }
}

SCENARIO("Database migration runner applies versioned upgrade and downgrade paths", "[database][migration]")
{
    GIVEN("an empty schema state")
    {
        auto const empty_state = merovingian::database::SchemaState{};

        WHEN("the initial upgrade and explicit downgrade are applied")
        {
            auto const upgrade_plan = merovingian::database::migration_plan_for(empty_state);
            auto const upgraded = merovingian::database::apply_migration_plan(empty_state, upgrade_plan);
            auto const second_plan = merovingian::database::migration_plan_for(upgraded.state);
            auto const compatible = merovingian::database::schema_state_is_compatible(upgraded.state);
            auto const downgrade_plan = merovingian::database::migration_plan_between(upgraded.state.version, 0U);
            auto const downgraded = merovingian::database::apply_migration_plan(upgraded.state, downgrade_plan);

            THEN("schema state is derived from migration statements and can be downgraded "
                 "explicitly")
            {
                REQUIRE(upgrade_plan.direction == merovingian::database::MigrationDirection::upgrade);
                REQUIRE(upgrade_plan.current_version == 0U);
                REQUIRE(upgrade_plan.target_version == merovingian::database::current_schema_version());
                REQUIRE(upgrade_plan.steps.size() == 7U);
                REQUIRE(upgrade_plan.steps.front().version == 1U);
                REQUIRE(upgrade_plan.steps.back().version == 7U);
                REQUIRE(upgraded.ok);
                REQUIRE(upgraded.state.version == merovingian::database::current_schema_version());
                REQUIRE(upgraded.state.applied_migrations.size() == 7U);
                // Schema v7 adds four sync-surface tables on top of the
                // initial inventory: room_account_data, to_device_messages,
                // device_list_changes, and presence_state.
                REQUIRE(upgraded.state.tables.size() == merovingian::database::initial_schema_tables().size() + 4U);
                REQUIRE(compatible.valid);
                REQUIRE(second_plan.steps.empty());
                REQUIRE(downgrade_plan.direction == merovingian::database::MigrationDirection::downgrade);
                REQUIRE(downgrade_plan.steps.size() == 7U);
                REQUIRE(downgraded.ok);
                REQUIRE(downgraded.state.version == 0U);
                REQUIRE(downgraded.state.tables.empty());
            }
        }
    }
}

SCENARIO("Database migration runner upgrades existing media schemas with metadata columns",
         "[database][migration][media]")
{
    GIVEN("a version one schema state with the original media table")
    {
        auto version_one_state = merovingian::database::SchemaState{};
        auto const initial_plan = merovingian::database::migration_plan_between(0U, 1U);
        auto const initialized = merovingian::database::apply_migration_plan(version_one_state, initial_plan);
        REQUIRE(initialized.ok);
        version_one_state = initialized.state;

        WHEN("the current migration plan is applied")
        {
            auto const media_plan = merovingian::database::migration_plan_for(version_one_state);
            auto const upgraded = merovingian::database::apply_migration_plan(version_one_state, media_plan);
            auto const compatible = merovingian::database::schema_state_is_compatible(upgraded.state);

            THEN("a dedicated media metadata migration records the schema upgrade")
            {
                REQUIRE(media_plan.current_version == 1U);
                REQUIRE(media_plan.target_version == merovingian::database::current_schema_version());
                REQUIRE(media_plan.steps.size() == 6U);
                REQUIRE(media_plan.steps.front().name == "media_metadata_columns");
                REQUIRE(media_plan.steps.front().statements.size() == 3U);
                REQUIRE(upgraded.ok);
                REQUIRE(upgraded.state.version == 7U);
                REQUIRE(upgraded.state.applied_migrations[1U].name == "media_metadata_columns");
                REQUIRE(upgraded.state.applied_migrations.back().name == "sync_surfaces_tables");
                REQUIRE(compatible.valid);
            }
        }
    }
}

SCENARIO("Database schema validation fails closed on incompatible state", "[database][migration]")
{
    GIVEN("a migrated schema missing a required table and a future schema")
    {
        auto opened = merovingian::database::open_persistent_store();
        REQUIRE(opened.ok);
        auto missing_table = opened.store.schema;
        missing_table.tables.clear();
        auto future_schema = opened.store.schema;
        future_schema.version = merovingian::database::current_schema_version() + 1U;

        WHEN("compatibility is checked")
        {
            auto const missing_result = merovingian::database::schema_state_is_compatible(missing_table);
            auto const future_result = merovingian::database::schema_state_is_compatible(future_schema);
            auto const rollback = merovingian::database::migration_rollback_policy();

            THEN("startup blockers are explicit")
            {
                REQUIRE_FALSE(missing_result.valid);
                REQUIRE(missing_result.reason.find("required table is missing") != std::string::npos);
                REQUIRE_FALSE(future_result.valid);
                REQUIRE(future_result.reason == "schema version is not compatible");
                REQUIRE(rollback.find("downgrade") != std::string_view::npos);
            }
        }
    }
}

SCENARIO("Persistent store records MVP homeserver data with hashed tokens only", "[database][persistence]")
{
    GIVEN("an opened persistent store")
    {
        auto opened = merovingian::database::open_persistent_store();
        REQUIRE(opened.ok);
        auto& store = opened.store;

        WHEN("users devices tokens rooms events state audit and admin actions are stored")
        {
            auto const user_ok = merovingian::database::store_user(
                store, {"@alice:example.org", "password-hash:v1:1", false, false, true});
            auto const device_ok =
                merovingian::database::store_device(store, {"@alice:example.org", "DEVICE1", "Alice laptop"});
            auto const bad_token_ok =
                merovingian::database::store_access_token(store, {"@alice:example.org", "DEVICE1", "plaintext", false});
            auto const token_ok = merovingian::database::store_access_token(
                store, {"@alice:example.org", "DEVICE1", "token-hash:v2:123", false});
            auto const room_ok = merovingian::database::store_room(store, {"!room1:example.org", "@alice:example.org"});
            auto const membership_ok =
                merovingian::database::store_membership(store, {"!room1:example.org", "@alice:example.org"});
            auto const message_event_ok =
                merovingian::database::store_event(store, {"$event1:example.org", "!room1:example.org",
                                                           "@alice:example.org", R"({"type":"m.room.message"})"});
            auto const message_state_ok = merovingian::database::store_state(
                store, {"!room1:example.org", "m.room.member", "@alice:example.org", "$event1:example.org"});
            auto const state_event_ok = merovingian::database::store_event(
                store, {"$event2:example.org", "!room1:example.org", "@alice:example.org",
                        R"({"type":"m.room.member","state_key":"@alice:example.org"})"});
            auto const state_ok = merovingian::database::store_state(
                store, {"!room1:example.org", "m.room.member", "@alice:example.org", "$event2:example.org"});
            auto const audit_ok = merovingian::database::append_audit_event(
                store, {"auth", "auth.login", "@alice:example.org", "DEVICE1", "accepted"});
            auto const admin_ok = merovingian::database::append_admin_action(
                store, {"@alice:example.org", "quarantine", "!room1:example.org"});
            auto const revoked = merovingian::database::revoke_access_token(store, "token-hash:v2:123");
            auto const valid = merovingian::database::validate_persistent_store(store);

            THEN("state rows are only accepted for matching state events")
            {
                REQUIRE(user_ok);
                REQUIRE(device_ok);
                REQUIRE_FALSE(bad_token_ok);
                REQUIRE(token_ok);
                REQUIRE(room_ok);
                REQUIRE(membership_ok);
                REQUIRE(message_event_ok);
                REQUIRE_FALSE(message_state_ok);
                REQUIRE(state_event_ok);
                REQUIRE(state_ok);
                REQUIRE(audit_ok);
                REQUIRE(admin_ok);
                REQUIRE(revoked == 1U);
                REQUIRE(valid.valid);
                REQUIRE(store.users.size() == 1U);
                REQUIRE(store.devices.size() == 1U);
                REQUIRE(store.access_tokens.front().revoked);
                REQUIRE(store.events.size() == 2U);
                REQUIRE(store.state.size() == 1U);
                REQUIRE(store.audit_log.size() == 1U);
                REQUIRE(store.admin_actions.size() == 1U);
                REQUIRE(merovingian::database::sensitive_values_are_redacted(store));
            }
        }
    }
}

SCENARIO("Persistent store transactions commit all rows or no rows", "[database][persistence][transaction]")
{
    GIVEN("a SQLite persistent store and a transaction whose second statement violates storage state")
    {
        auto const sqlite_path = unique_sqlite_path();
        std::filesystem::remove(sqlite_path);
        auto opened = merovingian::database::open_sqlite_persistent_store(sqlite_path.string());
        REQUIRE(opened.ok);
        auto& store = opened.store;

        auto const statements = std::vector<merovingian::database::PreparedStatement>{
            {"insert_room",
             "INSERT INTO rooms VALUES ($1, $2)", {{"!txn-room:example.org", false}, {"@alice:example.org", false}}},
            {"insert_room_duplicate",
             "INSERT INTO rooms VALUES ($1, $2)", {{"!txn-room:example.org", false}, {"@bob:example.org", false}}  },
        };

        WHEN("the transaction is committed")
        {
            auto const committed = merovingian::database::commit_persistent_transaction(store, statements);
            auto reopened = merovingian::database::open_sqlite_persistent_store(sqlite_path.string());
            REQUIRE(reopened.ok);

            THEN("the successful first statement is rolled back with the failed statement")
            {
                REQUIRE_FALSE(committed);
                REQUIRE(store.prepared_statements.empty());
                REQUIRE(reopened.store.rooms.empty());
            }
        }

        std::filesystem::remove(sqlite_path);
    }
}

SCENARIO("Persistent store offers atomic helpers for multi-row runtime mutations",
         "[database][persistence][transaction]")
{
    GIVEN("an opened persistent store")
    {
        auto opened = merovingian::database::open_persistent_store();
        REQUIRE(opened.ok);
        auto& store = opened.store;

        WHEN("a room membership and a state event are stored through transaction helpers")
        {
            auto const room_ok = merovingian::database::store_room_with_membership(
                store, {"!room-txn:example.org", "@alice:example.org"},
                {"!room-txn:example.org", "@alice:example.org"});
            auto const event_ok = merovingian::database::store_event_with_state(
                store,
                {"$state-txn:example.org", "!room-txn:example.org", "@alice:example.org",
                 R"({"type":"m.room.member","state_key":"@alice:example.org"})"},
                merovingian::database::PersistentStateEvent{"!room-txn:example.org", "m.room.member",
                                                            "@alice:example.org", "$state-txn:example.org"});

            THEN("all related rows become visible together")
            {
                REQUIRE(room_ok);
                REQUIRE(event_ok);
                REQUIRE(store.rooms.size() == 1U);
                REQUIRE(store.memberships.size() == 1U);
                REQUIRE(store.events.size() == 1U);
                REQUIRE(store.state.size() == 1U);
                REQUIRE(store.prepared_statements.size() == 4U);
            }
        }
    }
}

SCENARIO("Persistent store records server signing keys and event DAG metadata", "[database][persistence][events]")
{
    GIVEN("an opened persistent store with a room")
    {
        auto opened = merovingian::database::open_persistent_store();
        REQUIRE(opened.ok);
        auto& store = opened.store;
        REQUIRE(merovingian::database::store_room(store, {"!room-dag:example.org", "@alice:example.org"}));

        WHEN("a runtime signing key and a signed state-linked event are stored")
        {
            auto const key_ok = merovingian::database::store_server_signing_key(
                store, {"example.org", "ed25519:auto", "public-key-base64", 32503680000000ULL});
            auto const state_event_ok = merovingian::database::store_event_with_state(
                store,
                {"$state:example.org",
                 "!room-dag:example.org",
                 "@alice:example.org",
                 R"({"type":"m.room.member","state_key":"@alice:example.org"})",
                 1U,
                 0U,
                 {},
                 {},
                 {}},
                merovingian::database::PersistentStateEvent{"!room-dag:example.org", "m.room.member",
                                                            "@alice:example.org", "$state:example.org"});
            auto const message_event_ok = merovingian::database::store_event_with_state(
                store,
                {"$message:example.org",
                 "!room-dag:example.org",
                 "@alice:example.org",
                 R"({"type":"m.room.message","state_key":""})",
                 2U,
                 0U,
                 {"$state:example.org"},
                 {"$state:example.org"},
                 {{"example.org", "ed25519:auto",
                   "c3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzcw"}}},
                std::nullopt);
            auto const found_key = merovingian::database::find_server_signing_key(store, "example.org", "ed25519:auto");

            THEN("the signing key edge auth and signature rows are durable")
            {
                REQUIRE(key_ok);
                REQUIRE(state_event_ok);
                REQUIRE(message_event_ok);
                REQUIRE(found_key.has_value());
                REQUIRE(found_key->server_name == "example.org");
                REQUIRE(found_key->public_key == "public-key-base64");
                REQUIRE(store.events.size() == 2U);
                REQUIRE(store.events.back().depth == 2U);
                REQUIRE(store.event_edges.size() == 1U);
                REQUIRE(store.event_auth.size() == 1U);
                REQUIRE(store.event_signatures.size() == 1U);
                REQUIRE(store.event_edges.front().prev_event_id == "$state:example.org");
                REQUIRE(store.event_auth.front().auth_event_id == "$state:example.org");
                REQUIRE(store.event_signatures.front().server_name == "example.org");
                REQUIRE(store.prepared_statements.back().name == "insert_event_signature");
            }
        }
    }
}

SCENARIO("Persistent store replays outbound federation queue state after restart",
         "[database][persistence][federation]")
{
    GIVEN("a SQLite persistent store with destination retry state and a pending outbound transaction")
    {
        auto const sqlite_path = unique_sqlite_path();
        std::filesystem::remove(sqlite_path);
        auto opened = merovingian::database::open_sqlite_persistent_store(sqlite_path.string());
        REQUIRE(opened.ok);
        auto& store = opened.store;

        auto destination = merovingian::database::PersistentFederationDestination{};
        destination.server_name = "remote.example.org";
        destination.state = "backoff";
        destination.retry_after_ts = 5000U;
        destination.last_success_ts = 1000U;
        destination.consecutive_failures = 3U;

        auto transaction = merovingian::database::PersistentFederationTransaction{};
        transaction.transaction_id = "txn-1";
        transaction.server_name = "remote.example.org";
        transaction.method = "PUT";
        transaction.target = "/_matrix/federation/v1/send/txn-1";
        transaction.origin = "origin.example.org";
        transaction.origin_server_ts = "1234";
        transaction.body = R"({"pdus":[]})";
        transaction.retry_count = 2U;
        transaction.next_retry_ts = 5000U;

        WHEN("the rows are stored and the database is reopened")
        {
            auto const destination_ok = merovingian::database::store_federation_destination(store, destination);
            auto const transaction_ok = merovingian::database::store_federation_transaction(store, transaction);
            auto reopened = merovingian::database::open_sqlite_persistent_store(sqlite_path.string());
            REQUIRE(reopened.ok);

            THEN("destination retry state and pending transaction details are hydrated for replay")
            {
                REQUIRE(destination_ok);
                REQUIRE(transaction_ok);
                REQUIRE(reopened.store.federation_destinations.size() == 1U);
                REQUIRE(reopened.store.federation_transactions.size() == 1U);
                REQUIRE(reopened.store.federation_destinations.front().server_name == "remote.example.org");
                REQUIRE(reopened.store.federation_destinations.front().state == "backoff");
                REQUIRE(reopened.store.federation_destinations.front().retry_after_ts == 5000U);
                REQUIRE(reopened.store.federation_destinations.front().last_success_ts == 1000U);
                REQUIRE(reopened.store.federation_destinations.front().consecutive_failures == 3U);
                REQUIRE(reopened.store.federation_transactions.front().transaction_id == "txn-1");
                REQUIRE(reopened.store.federation_transactions.front().server_name == "remote.example.org");
                REQUIRE(reopened.store.federation_transactions.front().body == R"({"pdus":[]})");
                REQUIRE(reopened.store.federation_transactions.front().retry_count == 2U);
                REQUIRE(reopened.store.federation_transactions.front().next_retry_ts == 5000U);
            }
        }

        std::filesystem::remove(sqlite_path);
    }
}

SCENARIO("Persistent store records durable server-blind E2EE key state", "[database][persistence][key-api]")
{
    GIVEN("an opened persistent store")
    {
        auto opened = merovingian::database::open_persistent_store();
        REQUIRE(opened.ok);
        auto& store = opened.store;

        WHEN("device, one-time, fallback, cross-signing, signature, and backup keys are stored")
        {
            auto const device_ok = merovingian::database::store_device_key(
                store, {"@alice:example.org", "DEVICE1", R"({"algorithms":["m.megolm.v1.aes-sha2"]})"});
            auto const one_time_ok = merovingian::database::store_one_time_key(
                store, {"@alice:example.org", "DEVICE1", "signed_curve25519:AAA", R"({"key":"otk"})"});
            auto const fallback_ok = merovingian::database::store_fallback_key(
                store, {"@alice:example.org", "DEVICE1", "signed_curve25519:FB", R"({"key":"fallback"})"});
            auto const cross_signing_ok = merovingian::database::store_cross_signing_key(
                store, {"@alice:example.org", "master", R"({"keys":{"ed25519:master":"pub"}})"});
            auto const signature_ok = merovingian::database::store_key_signature(
                store, {"@alice:example.org", "@alice:example.org", "DEVICE1", R"({"signatures":{}})"});
            auto const backup_version_ok = merovingian::database::store_key_backup_version(
                store, {"@alice:example.org", "1", R"({"algorithm":"m.megolm_backup.v1"})"});
            auto const backup_session_ok = merovingian::database::store_key_backup_session(
                store, {"@alice:example.org", "1", "!room:example.org", "SESSION1", R"({"session_data":{}})"});
            auto claimed = merovingian::database::claim_one_time_key(store, "@alice:example.org", "DEVICE1");
            auto fallback = merovingian::database::find_fallback_key(store, "@alice:example.org", "DEVICE1");
            auto fallback_again = merovingian::database::find_fallback_key(store, "@alice:example.org", "DEVICE1");

            THEN("one-time keys are consumed while fallback and backup state remain durable")
            {
                REQUIRE(device_ok);
                REQUIRE(one_time_ok);
                REQUIRE(fallback_ok);
                REQUIRE(cross_signing_ok);
                REQUIRE(signature_ok);
                REQUIRE(backup_version_ok);
                REQUIRE(backup_session_ok);
                REQUIRE(claimed.has_value());
                REQUIRE(claimed->key_id == "signed_curve25519:AAA");
                REQUIRE(store.one_time_keys.empty());
                REQUIRE(fallback.has_value());
                REQUIRE(fallback_again.has_value());
                REQUIRE(store.fallback_keys.size() == 1U);
                REQUIRE(store.device_keys.size() == 1U);
                REQUIRE(store.cross_signing_keys.size() == 1U);
                REQUIRE(store.key_signatures.size() == 1U);
                REQUIRE(store.key_backup_versions.size() == 1U);
                REQUIRE(store.key_backup_sessions.size() == 1U);
                REQUIRE(merovingian::database::sensitive_values_are_redacted(store));
            }
        }
    }
}

SCENARIO("PostgreSQL connection policy rejects unsafe or ambiguous libpq inputs", "[database][postgresql]")
{
    GIVEN("empty and non-PostgreSQL connection strings")
    {
        WHEN("the connection strings are validated")
        {
            auto const empty = merovingian::database::validate_postgresql_conninfo("");
            auto const sqlite_path = merovingian::database::validate_postgresql_conninfo("/tmp/merovingian.sqlite3");
            auto const uri = merovingian::database::validate_postgresql_conninfo(
                "postgresql://merovingian:secret@db.example.org/merovingian?sslmode=verify-full");

            THEN("only explicit PostgreSQL libpq connection strings are accepted")
            {
                REQUIRE_FALSE(empty.allowed);
                REQUIRE(empty.reason == "PostgreSQL connection info must not be empty");
                REQUIRE_FALSE(sqlite_path.allowed);
                REQUIRE(sqlite_path.reason == "PostgreSQL connection info must use a PostgreSQL URI or key/value form");
                REQUIRE(uri.allowed);
            }
        }
    }
}

SCENARIO("PostgreSQL connection summaries redact credentials before logging", "[database][postgresql]")
{
    GIVEN("URI and key-value libpq connection strings containing passwords")
    {
        WHEN("redacted summaries are produced")
        {
            auto const uri = merovingian::database::redact_postgresql_conninfo(
                "postgresql://merovingian:secret@db.example.org/merovingian?sslmode=verify-full");
            auto const key_value = merovingian::database::redact_postgresql_conninfo(
                "host=db.example.org dbname=merovingian user=merovingian password=secret sslmode=verify-full");

            THEN("the password material is not disclosed")
            {
                REQUIRE(uri.find("secret") == std::string::npos);
                REQUIRE(uri.find("redacted") != std::string::npos);
                REQUIRE(key_value.find("secret") == std::string::npos);
                REQUIRE(key_value.find("password=redacted") != std::string::npos);
            }
        }
    }
}

SCENARIO("PostgreSQL schema bootstrap exposes current schema statements", "[database][postgresql][migration]")
{
    GIVEN("the current schema inventory")
    {
        WHEN("PostgreSQL bootstrap statements are created")
        {
            auto const statements = merovingian::database::postgresql_schema_bootstrap_statements();

            THEN("the bootstrap can create every core table and record current migrations")
            {
                REQUIRE(statements.size() >= merovingian::database::initial_schema_tables().size() + 2U);
                REQUIRE(statements.front().name == "postgresql_create_schema_migrations");
                REQUIRE(statements.front().sql.find("CREATE TABLE IF NOT EXISTS schema_migrations") == 0U);
                REQUIRE(statements.back().sql.find("ON CONFLICT") != std::string::npos);
            }
        }
    }
}

SCENARIO("Physical migration files load into validated migration plans", "[database][migration][files]")
{
    GIVEN("a temporary migration file with explicit statement names")
    {
        auto const directory = std::filesystem::temp_directory_path() / "merovingian-migration-file-test";
        std::filesystem::create_directories(directory);
        auto const file = directory / "003_policy_rules.sql";
        {
            auto output = std::ofstream{file};
            output << "-- merovingian-migration version=3 name=policy_rules direction=upgrade\n";
            output << "-- statement create_policy_rules_extra\n";
            output << "CREATE TABLE policy_rules_extra (rule_id TEXT PRIMARY KEY)\n";
        }

        WHEN("the migration directory is loaded")
        {
            auto const loaded = merovingian::database::load_migration_files(directory.string());

            THEN("the file becomes a validated migration step")
            {
                REQUIRE(loaded.ok);
                REQUIRE(loaded.steps.size() == 1U);
                REQUIRE(loaded.steps.front().version == 3U);
                REQUIRE(loaded.steps.front().name == "policy_rules");
                REQUIRE(loaded.steps.front().statements.size() == 1U);
                REQUIRE(merovingian::database::migration_step_is_valid(loaded.steps.front()).valid);
            }
        }

        std::filesystem::remove(file);
        std::filesystem::remove(directory);
    }
}

SCENARIO("Offline migrator plans require migration database role", "[database][migration][role]")
{
    GIVEN("runtime and migration database roles")
    {
        auto runtime_config = merovingian::config::DatabaseConfig{};
        runtime_config.role = merovingian::config::DatabaseRole::runtime;
        auto migration_config = merovingian::config::DatabaseConfig{};
        migration_config.role = merovingian::config::DatabaseRole::migration;

        WHEN("migrator plans are built")
        {
            auto const runtime_plan = merovingian::database::build_offline_migration_plan(runtime_config, 0U, 2U, {});
            auto const migration_plan =
                merovingian::database::build_offline_migration_plan(migration_config, 0U, 2U, {});

            THEN("only the migration role may run schema changes")
            {
                REQUIRE_FALSE(runtime_plan.ok);
                REQUIRE(runtime_plan.reason == "database migration requires database.role=migration");
                REQUIRE(migration_plan.ok);
                REQUIRE(migration_plan.plan.target_version == 2U);
            }
        }
    }
}

SCENARIO("Database schema inventory covers the core Matrix tables", "[database][schema]")
{
    GIVEN("the initial schema inventory")
    {
        WHEN("core table membership is queried")
        {
            auto const tables = merovingian::database::initial_schema_tables();
            auto const users_definition = merovingian::database::schema_table_definition("users");
            auto const current_state_definition = merovingian::database::schema_table_definition("current_state");
            auto const users_sql = users_definition.has_value()
                                       ? merovingian::database::create_table_sql(users_definition.value())
                                       : std::string{};
            auto const current_state_columns = current_state_definition.has_value()
                                                   ? current_state_definition.value().columns_sql
                                                   : std::string_view{};
            auto const unknown_is_core = merovingian::database::schema_table_is_core("not_a_table");

            THEN("required Matrix storage areas have table-specific definitions")
            {
                REQUIRE(tables.size() == 37U);
                REQUIRE(merovingian::database::current_schema_version() == 7U);
                REQUIRE(users_definition.has_value());
                REQUIRE(current_state_definition.has_value());
                REQUIRE(users_sql.find("user_id TEXT PRIMARY KEY") != std::string::npos);
                REQUIRE(current_state_columns.find("PRIMARY KEY (room_id, event_type, state_key)") !=
                        std::string_view::npos);
                REQUIRE_FALSE(unknown_is_core);
            }
        }
    }
}

SCENARIO("Persistent store includes event depth in event statements", "[database][persistence][events]")
{
    GIVEN("an opened persistent store with a room")
    {
        auto opened = merovingian::database::open_persistent_store();
        REQUIRE(opened.ok);
        auto& store = opened.store;
        REQUIRE(merovingian::database::store_room(store, {"!room-depth:example.org", "@alice:example.org"}));

        WHEN("events with explicit depth are stored")
        {
            auto const event_ok = merovingian::database::store_event(store, {"$depth1:example.org",
                                                                             "!room-depth:example.org",
                                                                             "@alice:example.org",
                                                                             R"({"type":"m.room.message"})",
                                                                             1U,
                                                                             0U,
                                                                             {},
                                                                             {},
                                                                             {}});
            auto const event_ok2 = merovingian::database::store_event(store, {"$depth2:example.org",
                                                                              "!room-depth:example.org",
                                                                              "@alice:example.org",
                                                                              R"({"type":"m.room.message"})",
                                                                              5U,
                                                                              0U,
                                                                              {},
                                                                              {},
                                                                              {}});

            THEN("depth is persisted in the event row and recoverable after storage")
            {
                REQUIRE(event_ok);
                REQUIRE(event_ok2);
                REQUIRE(store.events.size() == 2U);
                REQUIRE(store.events.front().depth == 1U);
                REQUIRE(store.events.back().depth == 5U);
                REQUIRE(store.prepared_statements.back().sql.find("$5") != std::string::npos);
            }
        }
    }
}

SCENARIO("Server signing keys are looked up by server identity and key ID", "[database][persistence][signing-key]")
{
    GIVEN("an opened persistent store with signing keys for different servers")
    {
        auto opened = merovingian::database::open_persistent_store();
        REQUIRE(opened.ok);
        auto& store = opened.store;

        auto const key_a_ok = merovingian::database::store_server_signing_key(
            store, {"server-a.org", "ed25519:auto", "public-key-a", 32503680000000ULL});
        auto const key_b_ok = merovingian::database::store_server_signing_key(
            store, {"server-b.org", "ed25519:auto", "public-key-b", 32503680000000ULL});

        WHEN("keys are looked up by server name and key ID")
        {
            auto const found_a = merovingian::database::find_server_signing_key(store, "server-a.org", "ed25519:auto");
            auto const found_b = merovingian::database::find_server_signing_key(store, "server-b.org", "ed25519:auto");
            auto const not_found =
                merovingian::database::find_server_signing_key(store, "server-c.org", "ed25519:auto");

            THEN("each server has its own key and unrelated lookups return nothing")
            {
                REQUIRE(key_a_ok);
                REQUIRE(key_b_ok);
                REQUIRE(found_a.has_value());
                REQUIRE(found_a->server_name == "server-a.org");
                REQUIRE(found_a->public_key == "public-key-a");
                REQUIRE(found_b.has_value());
                REQUIRE(found_b->server_name == "server-b.org");
                REQUIRE(found_b->public_key == "public-key-b");
                REQUIRE_FALSE(not_found.has_value());
            }
        }
    }
}
