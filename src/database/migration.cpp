// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/database/migration.hpp>
#include <merovingian/database/schema.hpp>

#include <algorithm>
#include <string>

namespace merovingian::database
{
namespace
{

[[nodiscard]] auto make_create_table_statement(std::string_view table_name) -> PreparedStatement
{
    return {
        "create_" + std::string{table_name},
        "CREATE TABLE " + std::string{table_name} + " (id TEXT PRIMARY KEY)",
        {},
    };
}

[[nodiscard]] auto has_table(SchemaState const& state, std::string_view table_name) noexcept -> bool
{
    return std::ranges::any_of(state.tables, [table_name](std::string const& table) {
        return table == table_name;
    });
}

[[nodiscard]] auto has_migration_record(SchemaState const& state, std::uint32_t version) noexcept -> bool
{
    return std::ranges::any_of(state.applied_migrations, [version](MigrationRecord const& record) {
        return record.version == version;
    });
}

} // namespace

auto migration_step_is_valid(MigrationStep const& step) -> MigrationValidationResult
{
    if (step.version == 0U)
    {
        return {false, "migration version must be non-zero"};
    }
    if (!statement_name_is_valid(step.name))
    {
        return {false, "migration name is invalid"};
    }
    if (step.statements.empty())
    {
        return {false, "migration has no statements"};
    }

    for (auto const& statement : step.statements)
    {
        auto const validation = prepared_statement_is_valid(statement);
        if (!validation.valid)
        {
            return {false, "migration statement invalid: " + validation.reason};
        }
    }

    return {true, {}};
}

auto migration_plan_is_valid(MigrationPlan const& plan) -> MigrationValidationResult
{
    if (plan.target_version < plan.current_version)
    {
        return {false, "downgrade migrations are not allowed"};
    }
    if (plan.current_version == plan.target_version)
    {
        return plan.steps.empty() ? MigrationValidationResult{true, {}}
                                  : MigrationValidationResult{false, "no-op migration plan must not contain steps"};
    }
    if (plan.steps.empty())
    {
        return {false, "upgrade migration plan has no steps"};
    }

    auto expected_version = plan.current_version + 1U;
    for (auto const& step : plan.steps)
    {
        if (step.version != expected_version)
        {
            return {false, "migration versions must be contiguous"};
        }
        auto const validation = migration_step_is_valid(step);
        if (!validation.valid)
        {
            return validation;
        }
        ++expected_version;
    }

    if (plan.steps.back().version != plan.target_version)
    {
        return {false, "migration plan does not reach target version"};
    }

    return {true, {}};
}

auto migration_plan_summary(MigrationPlan const& plan) -> std::string
{
    return "database migration plan current_version=" + std::to_string(plan.current_version)
        + " target_version=" + std::to_string(plan.target_version) + " steps=" + std::to_string(plan.steps.size());
}

auto initial_schema_migration() -> MigrationStep
{
    auto statements = std::vector<PreparedStatement>{};
    for (auto const table : initial_schema_tables())
    {
        statements.push_back(make_create_table_statement(table));
    }
    return {current_schema_version(), "initial_schema", std::move(statements)};
}

auto migration_plan_for(SchemaState const& state) -> MigrationPlan
{
    if (state.version == current_schema_version())
    {
        return {state.version, current_schema_version(), {}};
    }
    if (state.version == 0U)
    {
        return {0U, current_schema_version(), {initial_schema_migration()}};
    }
    return {state.version, current_schema_version(), {}};
}

auto apply_migration_plan(SchemaState state, MigrationPlan const& plan) -> MigrationApplyResult
{
    auto const validation = migration_plan_is_valid(plan);
    if (!validation.valid)
    {
        return {false, validation.reason, std::move(state)};
    }
    if (state.version != plan.current_version)
    {
        return {false, "schema state version does not match migration plan", std::move(state)};
    }

    for (auto const& step : plan.steps)
    {
        if (has_migration_record(state, step.version))
        {
            continue;
        }
        for (auto const& table : initial_schema_tables())
        {
            if (!has_table(state, table))
            {
                state.tables.emplace_back(table);
            }
        }
        state.applied_migrations.push_back({step.version, step.name});
        state.version = step.version;
    }

    return {true, {}, std::move(state)};
}

auto schema_state_is_compatible(SchemaState const& state) -> MigrationValidationResult
{
    if (state.version != current_schema_version())
    {
        return {false, "schema version is not compatible"};
    }
    if (!has_migration_record(state, current_schema_version()))
    {
        return {false, "current schema migration is not recorded"};
    }
    for (auto const table : initial_schema_tables())
    {
        if (!has_table(state, table))
        {
            return {false, "required table is missing: " + std::string{table}};
        }
    }
    return {true, {}};
}

auto migration_rollback_policy() noexcept -> std::string_view
{
    return "downgrade and rollback migrations are not applied automatically; restore from backup or run an operator-reviewed forward repair migration";
}

} // namespace merovingian::database
