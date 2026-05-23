// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/database/migration.hpp"

#include "merovingian/database/schema.hpp"
#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"

#include <algorithm>
#include <string>
#include <vector>

namespace merovingian::database
{
namespace
{

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields) -> void
    {
        LOG_DEBUG(observability::diagnostic_log_summary("migration", event, std::move(fields)));
    }

    constexpr auto initial_schema_version = std::uint32_t{1U};

    [[nodiscard]] auto make_create_table_statement(SchemaTableDefinition const& table) -> PreparedStatement
    {
        return {"create_" + std::string{table.name}, create_table_sql(table), {}};
    }

    [[nodiscard]] auto make_drop_table_statement(std::string_view table_name) -> PreparedStatement
    {
        return {"drop_" + std::string{table_name}, "DROP TABLE " + std::string{table_name}, {}};
    }

    [[nodiscard]] auto has_table(SchemaState const& state, std::string_view table_name) noexcept -> bool
    {
        return std::ranges::any_of(state.tables, [table_name](std::string const& table) {
            return table == table_name;
        });
    }

    [[nodiscard]] auto has_migration_record(SchemaState const& state, std::uint32_t version,
                                            MigrationDirection direction) noexcept -> bool
    {
        return std::ranges::any_of(state.applied_migrations, [version, direction](MigrationRecord const& record) {
            return record.version == version && record.direction == direction;
        });
    }

    [[nodiscard]] auto table_from_create_table(std::string_view sql) -> std::string
    {
        auto constexpr prefix = std::string_view{"CREATE TABLE "};
        if (!sql.starts_with(prefix))
        {
            return {};
        }
        auto const begin = prefix.size();
        auto const end = sql.find(' ', begin);
        return end == std::string_view::npos ? std::string{} : std::string{sql.substr(begin, end - begin)};
    }

    [[nodiscard]] auto table_from_drop_table(std::string_view sql) -> std::string
    {
        auto constexpr prefix = std::string_view{"DROP TABLE "};
        return sql.starts_with(prefix) ? std::string{sql.substr(prefix.size())} : std::string{};
    }

    auto add_table(SchemaState& state, std::string table_name) -> void
    {
        if (!table_name.empty() && !has_table(state, table_name))
        {
            state.tables.push_back(std::move(table_name));
        }
    }

    auto remove_table(SchemaState& state, std::string_view table_name) -> void
    {
        auto const [begin, end] = std::ranges::remove(state.tables, table_name);
        state.tables.erase(begin, end);
    }

    auto apply_statement_to_schema_state(SchemaState& state, PreparedStatement const& statement) -> bool
    {
        if (auto table = table_from_create_table(statement.sql); !table.empty())
        {
            add_table(state, std::move(table));
            return true;
        }
        if (auto table = table_from_drop_table(statement.sql); !table.empty())
        {
            remove_table(state, table);
            return true;
        }
        return statement.sql.starts_with("ALTER TABLE ");
    }

} // namespace

auto migration_direction_name(MigrationDirection direction) noexcept -> std::string_view
{
    return direction == MigrationDirection::upgrade ? "upgrade" : "downgrade";
}

auto migration_step_is_valid(MigrationStep const& step) -> MigrationValidationResult
{
    if (step.version == 0U && step.direction == MigrationDirection::upgrade)
    {
        return {false, "upgrade migration version must be non-zero"};
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
    if (plan.current_version == plan.target_version)
    {
        return plan.steps.empty() ? MigrationValidationResult{true, {}}
                                  : MigrationValidationResult{false, "no-op migration plan must not contain steps"};
    }
    if (plan.steps.empty())
    {
        return {false, "migration plan has no steps"};
    }
    if (plan.target_version > plan.current_version && plan.direction != MigrationDirection::upgrade)
    {
        return {false, "upgrade migration plan has wrong direction"};
    }
    if (plan.target_version < plan.current_version && plan.direction != MigrationDirection::downgrade)
    {
        return {false, "downgrade migration plan has wrong direction"};
    }

    auto expected_version =
        plan.direction == MigrationDirection::upgrade ? plan.current_version + 1U : plan.current_version - 1U;
    for (auto const& step : plan.steps)
    {
        if (step.version != expected_version || step.direction != plan.direction)
        {
            return {false, "migration versions must be contiguous"};
        }
        auto validation = migration_step_is_valid(step);
        if (!validation.valid)
        {
            return validation;
        }
        if (plan.direction == MigrationDirection::upgrade)
        {
            ++expected_version;
        }
        else if (expected_version > 0U)
        {
            --expected_version;
        }
    }

    return plan.steps.back().version == plan.target_version
               ? MigrationValidationResult{true, {}}
               : MigrationValidationResult{false, "migration plan does not reach target version"};
}

auto migration_plan_summary(MigrationPlan const& plan) -> std::string
{
    return "database migration plan direction=" + std::string{migration_direction_name(plan.direction)} +
           " current_version=" + std::to_string(plan.current_version) +
           " target_version=" + std::to_string(plan.target_version) + " steps=" + std::to_string(plan.steps.size());
}

auto initial_schema_migration() -> MigrationStep
{
    // The schema deploys at version 1 in its final shape. There are no live
    // databases to upgrade — every install lands on this initial schema and
    // remains there until a future schema change is required, at which
    // point a new migration step will be added.
    auto statements = std::vector<PreparedStatement>{};
    for (auto const& table : initial_schema_definitions())
    {
        statements.push_back(make_create_table_statement(table));
    }
    return {initial_schema_version, "initial_schema", std::move(statements), MigrationDirection::upgrade};
}

auto downgrade_initial_schema_migration() -> MigrationStep
{
    auto statements = std::vector<PreparedStatement>{};
    auto definitions = initial_schema_definitions();
    // Drop in reverse declaration order so dependent tables come down
    // before the ones they reference.
    for (auto iterator = definitions.rbegin(); iterator != definitions.rend(); ++iterator)
    {
        statements.push_back(make_drop_table_statement(iterator->name));
    }
    return {0U, "drop_initial_schema", std::move(statements), MigrationDirection::downgrade};
}

auto upgrade_migration_catalog() -> std::vector<MigrationStep>
{
    return {initial_schema_migration()};
}

auto downgrade_migration_catalog() -> std::vector<MigrationStep>
{
    return {downgrade_initial_schema_migration()};
}

auto migration_plan_between(std::uint32_t current_version, std::uint32_t target_version) -> MigrationPlan
{
    if (current_version == target_version)
    {
        return {current_version, target_version, {}, MigrationDirection::upgrade};
    }
    if (current_version > current_schema_version() || target_version > current_schema_version())
    {
        auto const direction =
            target_version > current_version ? MigrationDirection::upgrade : MigrationDirection::downgrade;
        return {current_version, target_version, {}, direction};
    }
    auto const direction =
        target_version > current_version ? MigrationDirection::upgrade : MigrationDirection::downgrade;
    auto const catalog =
        direction == MigrationDirection::upgrade ? upgrade_migration_catalog() : downgrade_migration_catalog();
    auto steps = std::vector<MigrationStep>{};
    if (direction == MigrationDirection::upgrade)
    {
        for (auto version = current_version + 1U; version <= target_version; ++version)
        {
            auto const iterator = std::ranges::find_if(catalog, [version](MigrationStep const& step) {
                return step.version == version && step.direction == MigrationDirection::upgrade;
            });
            if (iterator != catalog.end())
            {
                steps.push_back(*iterator);
            }
        }
    }
    else
    {
        for (auto version = current_version - 1U;; --version)
        {
            auto const iterator = std::ranges::find_if(catalog, [version](MigrationStep const& step) {
                return step.version == version && step.direction == MigrationDirection::downgrade;
            });
            if (iterator != catalog.end())
            {
                steps.push_back(*iterator);
            }
            if (version == target_version)
            {
                break;
            }
        }
    }
    return {current_version, target_version, std::move(steps), direction};
}

auto migration_plan_for(SchemaState const& state) -> MigrationPlan
{
    return migration_plan_between(state.version, current_schema_version());
}

auto apply_migration_plan(SchemaState state, MigrationPlan const& plan) -> MigrationApplyResult
{
    auto validation = migration_plan_is_valid(plan);
    if (!validation.valid)
    {
        log_diagnostic("plan.rejected",
                       {{"current_version", std::to_string(plan.current_version), false},
                        {"target_version",  std::to_string(plan.target_version),  false},
                        {"reason",          validation.reason,                     false}});
        return {false, validation.reason, std::move(state)};
    }
    if (state.version != plan.current_version)
    {
        log_diagnostic("plan.rejected",
                       {{"state_version",   std::to_string(state.version),         false},
                        {"current_version", std::to_string(plan.current_version),  false},
                        {"reason",          "schema state version does not match migration plan", false}});
        return {false, "schema state version does not match migration plan", std::move(state)};
    }
    for (auto const& step : plan.steps)
    {
        for (auto const& statement : step.statements)
        {
            if (!apply_statement_to_schema_state(state, statement))
            {
                log_diagnostic("step.failed",
                               {{"step_name",   step.name,         false},
                                {"version",     std::to_string(step.version), false},
                                {"direction",   std::string{migration_direction_name(step.direction)}, false},
                                {"statement",   statement.name,    false},
                                {"reason",      "migration statement cannot update schema state", false}});
                return {false, "migration statement cannot update schema state: " + statement.name, std::move(state)};
            }
        }
        log_diagnostic("step.applied",
                       {{"step_name",  step.name,         false},
                        {"version",    std::to_string(step.version), false},
                        {"direction",  std::string{migration_direction_name(step.direction)}, false},
                        {"statements", std::to_string(step.statements.size()), false}});
        state.applied_migrations.push_back({step.version, step.name, step.direction});
        state.version = step.version;
    }
    log_diagnostic("plan.complete",
                   {{"direction",       std::string{migration_direction_name(plan.direction)}, false},
                    {"current_version", std::to_string(plan.current_version),                 false},
                    {"target_version",  std::to_string(plan.target_version),                  false},
                    {"steps_applied",   std::to_string(plan.steps.size()),                    false}});
    return {true, {}, std::move(state)};
}

auto schema_state_is_compatible(SchemaState const& state) -> MigrationValidationResult
{
    if (state.version != current_schema_version())
    {
        return {false, "schema version is not compatible"};
    }
    if (!has_migration_record(state, current_schema_version(), MigrationDirection::upgrade))
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
    return "schema deploys at v1 in its final shape; downgrade plans exist for completeness "
           "and remain operator-controlled, paired with backup/restore validation";
}

} // namespace merovingian::database
