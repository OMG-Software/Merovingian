// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/database/connection.hpp>
#include <merovingian/database/migration.hpp>
#include <merovingian/database/schema.hpp>
#include <merovingian/database/statement.hpp>

#include <catch2/catch_test_macros.hpp>

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
        executed_statement_names.push_back(statement.name);
        return {true, {}, {{"ok"}}};
    }

    std::vector<std::string> executed_statement_names{};
};

[[nodiscard]] auto create_users_statement() -> merovingian::database::PreparedStatement
{
    return {
        "create_users",
        "CREATE TABLE users (id TEXT PRIMARY KEY)",
        {},
    };
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
        auto const invalid_name = merovingian::database::PreparedStatement{
            "select-user",
            "SELECT id FROM users WHERE id = $1",
            {},
        };
        auto const unsafe_sql = merovingian::database::PreparedStatement{
            "select_user",
            "SELECT id FROM users; SELECT id FROM devices",
            {},
        };

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

SCENARIO("Database executor validates statements before execution", "[database]")
{
    GIVEN("a recording executor and valid or invalid statements")
    {
        auto executor = RecordingExecutor{};
        auto const valid_statement = merovingian::database::PreparedStatement{"select_user", "SELECT id FROM users", {}};
        auto const invalid_statement = merovingian::database::PreparedStatement{"select-user", "SELECT id FROM users", {}};

        WHEN("validated execution is requested")
        {
            auto const valid_result = merovingian::database::execute_validated(executor, valid_statement);
            auto const invalid_result = merovingian::database::execute_validated(executor, invalid_statement);

            THEN("invalid statements fail before reaching the executor")
            {
                REQUIRE(valid_result.ok);
                REQUIRE_FALSE(invalid_result.ok);
                REQUIRE(invalid_result.error == "invalid statement name");
                REQUIRE(executor.executed_statement_names.size() == 1U);
                REQUIRE(executor.executed_statement_names.front() == "select_user");
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
            {"secret-token-hash", true},
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

SCENARIO("Database migration plans must be contiguous and forward-only", "[database][migration]")
{
    GIVEN("valid, downgrade, and non-contiguous migration plans")
    {
        auto const valid_plan = merovingian::database::MigrationPlan{
            0U,
            2U,
            {
                merovingian::database::MigrationStep{1U, "create_users", {create_users_statement()}},
                merovingian::database::MigrationStep{2U, "create_devices", {{"create_devices", "CREATE TABLE devices (id TEXT PRIMARY KEY)", {}}}},
            },
        };
        auto const downgrade_plan = merovingian::database::MigrationPlan{2U, 1U, {}};
        auto const gap_plan = merovingian::database::MigrationPlan{
            0U,
            2U,
            {merovingian::database::MigrationStep{2U, "create_devices", {{"create_devices", "CREATE TABLE devices (id TEXT PRIMARY KEY)", {}}}}},
        };

        WHEN("the migration plans are validated")
        {
            auto const valid_result = merovingian::database::migration_plan_is_valid(valid_plan);
            auto const downgrade_result = merovingian::database::migration_plan_is_valid(downgrade_plan);
            auto const gap_result = merovingian::database::migration_plan_is_valid(gap_plan);
            auto const summary = merovingian::database::migration_plan_summary(valid_plan);

            THEN("only the contiguous forward plan is accepted")
            {
                REQUIRE(valid_result.valid);
                REQUIRE_FALSE(downgrade_result.valid);
                REQUIRE(downgrade_result.reason == "downgrade migrations are not allowed");
                REQUIRE_FALSE(gap_result.valid);
                REQUIRE(gap_result.reason == "migration versions must be contiguous");
                REQUIRE(summary == "database migration plan current_version=0 target_version=2 steps=2");
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
            auto const users_is_core = merovingian::database::schema_table_is_core("users");
            auto const events_is_core = merovingian::database::schema_table_is_core("events");
            auto const access_tokens_is_core = merovingian::database::schema_table_is_core("access_tokens");
            auto const unknown_is_core = merovingian::database::schema_table_is_core("not_a_table");

            THEN("required Matrix storage areas are present")
            {
                REQUIRE(tables.size() == 32U);
                REQUIRE(users_is_core);
                REQUIRE(events_is_core);
                REQUIRE(access_tokens_is_core);
                REQUIRE_FALSE(unknown_is_core);
            }
        }
    }
}
