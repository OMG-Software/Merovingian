// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Unit tests for database schema helpers and migration validation.
// Focuses on error, failure, and anomaly paths not covered by
// test_database_persistence.cpp (which covers migration plan
// direction/contiguity and the full upgrade/downgrade runners).
//
// Coverage:
//   - quote_sqlite_identifier: valid names, empty rejected, injection chars rejected
//   - schema_table_is_core: core tables vs unknown names
//   - schema_table_definition: known vs unknown table lookup
//   - create_table_sql: core table generates DDL; non-core table fails closed
//   - current_schema_version: non-zero contract
//   - initial_schema_tables: non-empty invariant
//   - migration_step_is_valid: version-zero upgrade, bad name, empty statements,
//                              invalid statement SQL
//   - migration_direction_name: round-trips upgrade/downgrade
//   - migration_rollback_policy: non-empty policy string
//   - migration_plan_between: same-version no-op, v0→v1, beyond-catalog
//   - apply_migration_plan: state version mismatch fails closed
//   - migration_plan_is_valid: no-op valid/invalid, direction mismatch, no steps

#include "merovingian/database/migration.hpp"
#include "merovingian/database/schema.hpp"
#include "merovingian/database/statement.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <string>

// --- quote_sqlite_identifier -------------------------------------------------

SCENARIO("quote_sqlite_identifier accepts alphanumeric-underscore names and wraps them in double quotes",
         "[database][schema][identifier]")
{
    GIVEN("valid SQLite identifier names")
    {
        WHEN("a simple table name is quoted")
        {
            auto const result = merovingian::database::quote_sqlite_identifier("users");

            THEN("the name is wrapped in double quotes")
            {
                REQUIRE(result.has_value());
                REQUIRE(*result == "\"users\"");
            }
        }

        WHEN("an identifier with underscores and digits is quoted")
        {
            auto const result = merovingian::database::quote_sqlite_identifier("schema_migrations");

            THEN("underscores and digits are permitted")
            {
                REQUIRE(result.has_value());
                REQUIRE(*result == "\"schema_migrations\"");
            }
        }

        WHEN("a mixed-case identifier is quoted")
        {
            auto const result = merovingian::database::quote_sqlite_identifier("DeviceKeys123");

            THEN("mixed case passes through unchanged")
            {
                REQUIRE(result.has_value());
                REQUIRE(*result == "\"DeviceKeys123\"");
            }
        }
    }
}

SCENARIO("quote_sqlite_identifier rejects empty identifier", "[database][schema][identifier][security]")
{
    GIVEN("an empty identifier string")
    {
        WHEN("the empty string is quoted")
        {
            auto const result = merovingian::database::quote_sqlite_identifier("");

            THEN("quoting fails to prevent a bare empty-string SQL identifier")
            {
                REQUIRE_FALSE(result.has_value());
            }
        }
    }
}

SCENARIO("quote_sqlite_identifier rejects identifiers with SQL-injection characters",
         "[database][schema][identifier][security]")
{
    GIVEN("identifiers containing characters outside [A-Za-z0-9_]")
    {
        WHEN("an identifier with a semicolon is quoted")
        {
            auto const result = merovingian::database::quote_sqlite_identifier("users; DROP TABLE users");

            THEN("the semicolon is rejected to prevent SQL injection")
            {
                REQUIRE_FALSE(result.has_value());
            }
        }

        WHEN("an identifier with an embedded double-quote is quoted")
        {
            auto const result = merovingian::database::quote_sqlite_identifier("my\"table");

            THEN("the embedded quote is rejected")
            {
                REQUIRE_FALSE(result.has_value());
            }
        }

        WHEN("an identifier with a hyphen is quoted")
        {
            auto const result = merovingian::database::quote_sqlite_identifier("my-table");

            THEN("hyphens are rejected — only underscores are permitted as word separators")
            {
                REQUIRE_FALSE(result.has_value());
            }
        }

        WHEN("an identifier with a space is quoted")
        {
            auto const result = merovingian::database::quote_sqlite_identifier("my table");

            THEN("spaces are rejected")
            {
                REQUIRE_FALSE(result.has_value());
            }
        }

        WHEN("an identifier with a newline is quoted")
        {
            auto const result = merovingian::database::quote_sqlite_identifier("my\ntable");

            THEN("control characters are rejected")
            {
                REQUIRE_FALSE(result.has_value());
            }
        }
    }
}

// --- schema_table_is_core / schema_table_definition -------------------------

SCENARIO("schema_table_is_core identifies core schema tables and rejects unknown names", "[database][schema][core]")
{
    GIVEN("core and non-core table names")
    {
        WHEN("core table names are tested")
        {
            THEN("users, devices, and schema_migrations are core tables")
            {
                REQUIRE(merovingian::database::schema_table_is_core("users"));
                REQUIRE(merovingian::database::schema_table_is_core("devices"));
                REQUIRE(merovingian::database::schema_table_is_core("schema_migrations"));
            }
        }

        WHEN("an unknown or injected table name is tested")
        {
            THEN("non-core tables are rejected")
            {
                REQUIRE_FALSE(merovingian::database::schema_table_is_core("injected_table"));
                REQUIRE_FALSE(merovingian::database::schema_table_is_core(""));
                REQUIRE_FALSE(merovingian::database::schema_table_is_core("users; DROP TABLE users"));
            }
        }
    }
}

SCENARIO("schema_table_definition returns a definition for core tables and nullopt for unknown names",
         "[database][schema][core]")
{
    GIVEN("a core table name and an unknown name")
    {
        WHEN("a core table definition is looked up")
        {
            auto const definition = merovingian::database::schema_table_definition("users");

            THEN("the definition is present and carries the table name")
            {
                REQUIRE(definition.has_value());
                REQUIRE(definition->name == "users");
                REQUIRE_FALSE(definition->columns_sql.empty());
            }
        }

        WHEN("an unknown table name is looked up")
        {
            auto const definition = merovingian::database::schema_table_definition("nonexistent_table");

            THEN("nullopt is returned — fail closed for unknown tables")
            {
                REQUIRE_FALSE(definition.has_value());
            }
        }
    }
}

// --- create_table_sql --------------------------------------------------------

SCENARIO("create_table_sql generates DDL for core tables and fails closed for non-core names",
         "[database][schema][ddl]")
{
    GIVEN("a core table definition and a non-core table definition")
    {
        auto const core_def = merovingian::database::schema_table_definition("users");
        REQUIRE(core_def.has_value());

        auto non_core = merovingian::database::SchemaTableDefinition{};
        non_core.name = "attacker_table";
        non_core.columns_sql = "id TEXT PRIMARY KEY";

        WHEN("DDL is generated for the core table")
        {
            auto const sql = merovingian::database::create_table_sql(*core_def);

            THEN("CREATE TABLE SQL is produced with a quoted identifier")
            {
                REQUIRE(sql.has_value());
                REQUIRE(sql->find("CREATE TABLE") != std::string::npos);
                REQUIRE(sql->find("\"users\"") != std::string::npos);
            }
        }

        WHEN("DDL is requested for a non-core table definition")
        {
            auto const sql = merovingian::database::create_table_sql(non_core);

            THEN("nullopt is returned to prevent arbitrary table creation")
            {
                REQUIRE_FALSE(sql.has_value());
            }
        }
    }
}

// --- current_schema_version / initial_schema_tables -------------------------

SCENARIO("current_schema_version returns a non-zero version and initial_schema_tables is non-empty",
         "[database][schema][invariant]")
{
    GIVEN("the compiled schema constants")
    {
        WHEN("the schema version is queried")
        {
            auto const version = merovingian::database::current_schema_version();

            THEN("the version is non-zero — version 0 is the empty-schema sentinel")
            {
                REQUIRE(version > 0U);
            }
        }

        WHEN("the initial schema tables are queried")
        {
            auto const tables = merovingian::database::initial_schema_tables();

            THEN("the list is non-empty and every entry is a core table")
            {
                REQUIRE_FALSE(tables.empty());
                for (auto const& table_name : tables)
                {
                    REQUIRE(merovingian::database::schema_table_is_core(table_name));
                }
            }
        }
    }
}

// --- migration_step_is_valid -------------------------------------------------

SCENARIO("migration_step_is_valid rejects upgrade steps with version zero", "[database][migration][step]")
{
    GIVEN("an upgrade migration step carrying version 0")
    {
        auto step = merovingian::database::MigrationStep{};
        step.version = 0U;
        step.name = "initial_schema";
        step.direction = merovingian::database::MigrationDirection::upgrade;
        step.statements.push_back({"create_x", "CREATE TABLE \"x\" (id TEXT PRIMARY KEY)", {}});

        WHEN("the step is validated")
        {
            auto const result = merovingian::database::migration_step_is_valid(step);

            THEN("the step is rejected because version 0 is reserved for the empty-schema state")
            {
                REQUIRE_FALSE(result.valid);
                REQUIRE(result.reason == "upgrade migration version must be non-zero");
            }
        }
    }
}

SCENARIO("migration_step_is_valid accepts a downgrade step at version zero", "[database][migration][step]")
{
    // Downgrade steps run in the opposite direction and their version field
    // identifies the schema state they target (0 = drop everything), so
    // version 0 is valid for a downgrade.
    GIVEN("a downgrade migration step at version 0")
    {
        auto step = merovingian::database::MigrationStep{};
        step.version = 0U;
        step.name = "drop_initial_schema";
        step.direction = merovingian::database::MigrationDirection::downgrade;
        step.statements.push_back({"drop_x", "DROP TABLE \"x\"", {}});

        WHEN("the step is validated")
        {
            auto const result = merovingian::database::migration_step_is_valid(step);

            THEN("version 0 is allowed for downgrade steps")
            {
                REQUIRE(result.valid);
            }
        }
    }
}

SCENARIO("migration_step_is_valid rejects steps whose name fails the statement-name rules",
         "[database][migration][step]")
{
    GIVEN("a migration step with a hyphenated name")
    {
        auto step = merovingian::database::MigrationStep{};
        step.version = 2U;
        step.name = "add-new-column"; // hyphens violate statement_name_is_valid
        step.direction = merovingian::database::MigrationDirection::upgrade;
        step.statements.push_back({"alter_users", "ALTER TABLE \"users\" ADD COLUMN phone TEXT", {}});

        WHEN("the step is validated")
        {
            auto const result = merovingian::database::migration_step_is_valid(step);

            THEN("the step is rejected with an invalid-name reason")
            {
                REQUIRE_FALSE(result.valid);
                REQUIRE(result.reason == "migration name is invalid");
            }
        }
    }
}

SCENARIO("migration_step_is_valid rejects steps with no statements", "[database][migration][step]")
{
    GIVEN("a migration step with an empty statements list")
    {
        auto step = merovingian::database::MigrationStep{};
        step.version = 2U;
        step.name = "empty_migration";
        step.direction = merovingian::database::MigrationDirection::upgrade;
        // statements left empty

        WHEN("the step is validated")
        {
            auto const result = merovingian::database::migration_step_is_valid(step);

            THEN("the step is rejected — a migration with no statements cannot change schema state")
            {
                REQUIRE_FALSE(result.valid);
                REQUIRE(result.reason == "migration has no statements");
            }
        }
    }
}

SCENARIO("migration_step_is_valid rejects steps containing multi-statement SQL",
         "[database][migration][step][security]")
{
    GIVEN("a migration step whose statement contains a semicolon-delimited second statement")
    {
        auto step = merovingian::database::MigrationStep{};
        step.version = 2U;
        step.name = "add_column";
        step.direction = merovingian::database::MigrationDirection::upgrade;
        // Two statements in one SQL string — rejected to prevent injection via
        // migration files.
        step.statements.push_back(
            {"add_column_and_drop", "ALTER TABLE \"users\" ADD COLUMN phone TEXT; DROP TABLE users", {}});

        WHEN("the step is validated")
        {
            auto const result = merovingian::database::migration_step_is_valid(step);

            THEN("the step is rejected because the statement contains multiple SQL commands")
            {
                REQUIRE_FALSE(result.valid);
                REQUIRE(result.reason.find("migration statement invalid") != std::string::npos);
            }
        }
    }
}

// --- migration_direction_name ------------------------------------------------

SCENARIO("migration_direction_name round-trips upgrade and downgrade to their canonical strings",
         "[database][migration][direction]")
{
    GIVEN("the two migration directions")
    {
        WHEN("upgrade direction is named")
        {
            auto const name =
                merovingian::database::migration_direction_name(merovingian::database::MigrationDirection::upgrade);

            THEN("the name is 'upgrade'")
            {
                REQUIRE(name == "upgrade");
            }
        }

        WHEN("downgrade direction is named")
        {
            auto const name =
                merovingian::database::migration_direction_name(merovingian::database::MigrationDirection::downgrade);

            THEN("the name is 'downgrade'")
            {
                REQUIRE(name == "downgrade");
            }
        }
    }
}

// --- migration_rollback_policy -----------------------------------------------

SCENARIO("migration_rollback_policy returns a non-empty human-readable policy string", "[database][migration][policy]")
{
    GIVEN("no preconditions")
    {
        WHEN("the rollback policy is queried")
        {
            auto const policy = merovingian::database::migration_rollback_policy();

            THEN("the policy string is non-empty and describes the rollback behaviour")
            {
                REQUIRE_FALSE(policy.empty());
            }
        }
    }
}

// --- migration_plan_between --------------------------------------------------

SCENARIO("migration_plan_between produces an empty no-op plan when current equals target",
         "[database][migration][plan]")
{
    GIVEN("current and target version are both 1")
    {
        WHEN("a migration plan is requested between the same version")
        {
            auto const plan = merovingian::database::migration_plan_between(1U, 1U);

            THEN("the plan has no steps and is a valid no-op")
            {
                REQUIRE(plan.current_version == 1U);
                REQUIRE(plan.target_version == 1U);
                REQUIRE(plan.steps.empty());
                auto const valid = merovingian::database::migration_plan_is_valid(plan);
                REQUIRE(valid.valid);
            }
        }
    }
}

SCENARIO("migration_plan_between produces an upgrade plan from version 0 to the current schema version",
         "[database][migration][plan]")
{
    GIVEN("current version 0 (empty database) and the live schema version as target")
    {
        auto const target = merovingian::database::current_schema_version();

        WHEN("a migration plan is requested")
        {
            auto const plan = merovingian::database::migration_plan_between(0U, target);

            THEN("the plan is a valid upgrade with the expected number of steps")
            {
                REQUIRE(plan.direction == merovingian::database::MigrationDirection::upgrade);
                REQUIRE(plan.steps.size() == static_cast<std::size_t>(target));
                auto const valid = merovingian::database::migration_plan_is_valid(plan);
                REQUIRE(valid.valid);
            }
        }
    }
}

SCENARIO("migration_plan_between produces an empty plan when the target version exceeds the catalog",
         "[database][migration][plan]")
{
    GIVEN("a target version beyond the current schema catalog")
    {
        auto const beyond = merovingian::database::current_schema_version() + 100U;

        WHEN("a migration plan is requested for the future version")
        {
            auto const plan = merovingian::database::migration_plan_between(0U, beyond);

            THEN("no steps are produced — the catalog cannot supply future migrations")
            {
                REQUIRE(plan.steps.empty());
            }
        }
    }
}

// --- apply_migration_plan ----------------------------------------------------

SCENARIO("apply_migration_plan fails closed when the state version does not match the plan",
         "[database][migration][apply]")
{
    GIVEN("a valid upgrade plan from v0→v1 applied against a state already at version 2")
    {
        // migration_plan_between(0, 1) produces a valid plan (passes migration_plan_is_valid).
        // Applying it against state.version=2 (not 0) triggers the version-mismatch guard
        // inside apply_migration_plan — distinct from any plan-validation failure.
        auto const plan = merovingian::database::migration_plan_between(0U, 1U);
        auto const valid = merovingian::database::migration_plan_is_valid(plan);
        REQUIRE(valid.valid); // sanity: plan must be valid to reach the state-version check

        auto state = merovingian::database::SchemaState{};
        state.version = 2U; // database is ahead — does not match plan.current_version (0)

        WHEN("the plan is applied against a state whose version does not match")
        {
            auto const result = merovingian::database::apply_migration_plan(state, plan);

            THEN("the plan is rejected with a version-mismatch reason")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.reason.find("schema state version does not match") != std::string::npos);
            }
        }
    }
}

// --- migration_plan_is_valid -----------------------------------------------------

SCENARIO("migration_plan_is_valid accepts a no-op plan with no steps", "[database][migration][plan_valid]")
{
    GIVEN("a plan where current_version equals target_version and steps is empty")
    {
        auto const plan = merovingian::database::migration_plan_between(0U, 0U);

        WHEN("the plan is validated")
        {
            auto const result = merovingian::database::migration_plan_is_valid(plan);

            THEN("a no-op plan with no steps is valid")
            {
                REQUIRE(result.valid);
            }
        }
    }
}

SCENARIO("migration_plan_is_valid rejects a no-op plan that contains steps", "[database][migration][plan_valid][error]")
{
    GIVEN("a plan with current_version == target_version but at least one step")
    {
        auto plan = merovingian::database::MigrationPlan{};
        plan.current_version = 1U;
        plan.target_version = 1U;
        plan.direction = merovingian::database::MigrationDirection::upgrade;
        auto step = merovingian::database::MigrationStep{};
        step.version = 1U;
        step.name = "phantom_step";
        step.direction = merovingian::database::MigrationDirection::upgrade;
        step.statements.push_back({"create_x", "CREATE TABLE \"x\" (id TEXT PRIMARY KEY)", {}});
        plan.steps.push_back(std::move(step));

        WHEN("the plan is validated")
        {
            auto const result = merovingian::database::migration_plan_is_valid(plan);

            THEN("the plan is rejected — a no-op must not carry steps")
            {
                REQUIRE_FALSE(result.valid);
                REQUIRE(result.reason == "no-op migration plan must not contain steps");
            }
        }
    }
}

SCENARIO("migration_plan_is_valid rejects an upgrade plan with no steps", "[database][migration][plan_valid][error]")
{
    GIVEN("a plan where target > current but steps is empty")
    {
        auto plan = merovingian::database::MigrationPlan{};
        plan.current_version = 0U;
        plan.target_version = 1U;
        plan.direction = merovingian::database::MigrationDirection::upgrade;

        WHEN("the plan is validated")
        {
            auto const result = merovingian::database::migration_plan_is_valid(plan);

            THEN("the plan is rejected — an upgrade without steps cannot advance the schema")
            {
                REQUIRE_FALSE(result.valid);
                REQUIRE(result.reason == "migration plan has no steps");
            }
        }
    }
}

SCENARIO("migration_plan_is_valid rejects an upgrade plan whose direction is set to downgrade",
         "[database][migration][plan_valid][error]")
{
    GIVEN("a plan where target > current but direction is downgrade")
    {
        auto plan = merovingian::database::MigrationPlan{};
        plan.current_version = 0U;
        plan.target_version = 1U;
        plan.direction = merovingian::database::MigrationDirection::downgrade; // wrong direction
        auto step = merovingian::database::MigrationStep{};
        step.version = 1U;
        step.name = "add_users";
        step.direction = merovingian::database::MigrationDirection::upgrade;
        step.statements.push_back({"create_users", "CREATE TABLE \"users\" (id TEXT PRIMARY KEY)", {}});
        plan.steps.push_back(std::move(step));

        WHEN("the plan is validated")
        {
            auto const result = merovingian::database::migration_plan_is_valid(plan);

            THEN("the plan is rejected — direction must match the version delta")
            {
                REQUIRE_FALSE(result.valid);
                REQUIRE(result.reason == "upgrade migration plan has wrong direction");
            }
        }
    }
}

SCENARIO("migration_plan_is_valid rejects a downgrade plan whose direction is set to upgrade",
         "[database][migration][plan_valid][error]")
{
    GIVEN("a plan where target < current but direction is upgrade")
    {
        auto plan = merovingian::database::MigrationPlan{};
        plan.current_version = 1U;
        plan.target_version = 0U;
        plan.direction = merovingian::database::MigrationDirection::upgrade; // wrong direction
        auto step = merovingian::database::MigrationStep{};
        step.version = 0U;
        step.name = "drop_users";
        step.direction = merovingian::database::MigrationDirection::downgrade;
        step.statements.push_back({"drop_users", "DROP TABLE \"users\"", {}});
        plan.steps.push_back(std::move(step));

        WHEN("the plan is validated")
        {
            auto const result = merovingian::database::migration_plan_is_valid(plan);

            THEN("the plan is rejected — direction must match the version delta")
            {
                REQUIRE_FALSE(result.valid);
                REQUIRE(result.reason == "downgrade migration plan has wrong direction");
            }
        }
    }
}

SCENARIO("migration_plan_is_valid accepts a real upgrade plan from the catalog", "[database][migration][plan_valid]")
{
    GIVEN("a plan produced by migration_plan_between from version 0 to current")
    {
        auto const plan =
            merovingian::database::migration_plan_between(0U, merovingian::database::current_schema_version());

        WHEN("the plan is validated")
        {
            auto const result = merovingian::database::migration_plan_is_valid(plan);

            THEN("the catalog-derived plan is valid")
            {
                REQUIRE(result.valid);
                REQUIRE(result.reason.empty());
            }
        }
    }
}
