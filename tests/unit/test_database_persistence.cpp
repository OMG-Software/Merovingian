// SPDX-License-Identifier: GPL-3.0-or-later

#include <catch2/catch_test_macros.hpp>
#include <merovingian/database/connection.hpp>
#include <merovingian/database/migration.hpp>
#include <merovingian/database/persistent_store.hpp>
#include <merovingian/database/schema.hpp>
#include <merovingian/database/statement.hpp>
#include <string>
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
                REQUIRE(upgrade_plan.steps.size() == 2U);
                REQUIRE(upgrade_plan.steps.front().version == 1U);
                REQUIRE(upgrade_plan.steps.back().version == 2U);
                REQUIRE(upgraded.ok);
                REQUIRE(upgraded.state.version == merovingian::database::current_schema_version());
                REQUIRE(upgraded.state.applied_migrations.size() == 2U);
                REQUIRE(upgraded.state.tables.size() == merovingian::database::initial_schema_tables().size());
                REQUIRE(compatible.valid);
                REQUIRE(second_plan.steps.empty());
                REQUIRE(downgrade_plan.direction == merovingian::database::MigrationDirection::downgrade);
                REQUIRE(downgrade_plan.steps.size() == 2U);
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
                REQUIRE(media_plan.steps.size() == 1U);
                REQUIRE(media_plan.steps.front().name == "media_metadata_columns");
                REQUIRE(media_plan.steps.front().statements.size() == 3U);
                REQUIRE(upgraded.ok);
                REQUIRE(upgraded.state.version == 2U);
                REQUIRE(upgraded.state.applied_migrations.back().name == "media_metadata_columns");
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
                REQUIRE(tables.size() == 33U);
                REQUIRE(merovingian::database::current_schema_version() == 2U);
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
