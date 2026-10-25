// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/database/migration.hpp"

#include "merovingian/database/schema.hpp"
#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"

#include <algorithm>
#include <optional>
#include <string>
#include <vector>

namespace merovingian::database
{
namespace
{

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields,
                        observability::LogEventSeverity severity = observability::LogEventSeverity::debug) -> void
    {
        observability::log_diagnostic("migration", event, fields, severity);
    }

    constexpr auto initial_schema_version = std::uint32_t{1U};
    constexpr auto initial_schema_name = std::string_view{"initial_schema"};

    [[nodiscard]] auto make_create_table_statement(SchemaTableDefinition const& table)
        -> std::optional<PreparedStatement>
    {
        auto sql = create_table_sql(table);
        if (!sql.has_value())
        {
            return std::nullopt;
        }
        return PreparedStatement{"create_" + std::string{table.name}, std::move(*sql), {}};
    }

    [[nodiscard]] auto make_create_index_statement(SchemaIndexDefinition const& index)
        -> std::optional<PreparedStatement>
    {
        auto sql = create_index_sql(index);
        if (!sql.has_value())
        {
            return std::nullopt;
        }
        return PreparedStatement{"create_" + std::string{index.name}, std::move(*sql), {}};
    }

    [[nodiscard]] auto make_drop_table_statement(std::string_view table_name) -> std::optional<PreparedStatement>
    {
        if (!schema_table_is_core(table_name))
        {
            return std::nullopt;
        }

        auto quoted = quote_sqlite_identifier(table_name);
        if (!quoted.has_value())
        {
            return std::nullopt;
        }

        return PreparedStatement{"drop_" + std::string{table_name}, "DROP TABLE " + std::move(*quoted), {}};
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

    [[nodiscard]] auto unquote_sqlite_identifier(std::string_view value) -> std::string
    {
        if (value.size() >= 2U && value.front() == '"' && value.back() == '"')
        {
            value.remove_prefix(1);
            value.remove_suffix(1);
        }

        auto result = std::string{};
        result.reserve(value.size());
        for (auto index = std::size_t{0U}; index < value.size(); ++index)
        {
            if (value[index] == '"' && index + 1U < value.size() && value[index + 1U] == '"')
            {
                // SQLite escapes a literal double quote as two double quotes.
                result.push_back('"');
                ++index;
            }
            else
            {
                result.push_back(value[index]);
            }
        }
        return result;
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
        if (end == std::string_view::npos)
        {
            return {};
        }
        return unquote_sqlite_identifier(sql.substr(begin, end - begin));
    }

    [[nodiscard]] auto table_from_drop_table(std::string_view sql) -> std::string
    {
        auto constexpr prefix = std::string_view{"DROP TABLE "};
        return sql.starts_with(prefix) ? unquote_sqlite_identifier(sql.substr(prefix.size())) : std::string{};
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

    [[nodiscard]] auto is_data_only_statement(std::string_view sql) noexcept -> bool
    {
        return sql.starts_with("INSERT ") || sql.starts_with("UPDATE ") || sql.starts_with("DELETE ");
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
        if (statement.sql.starts_with("ALTER TABLE "))
        {
            return true;
        }
        // Indexes are not part of the table set SchemaState tracks (they are
        // neither created nor dropped from `state.tables`), so a CREATE
        // INDEX/DROP INDEX statement -- like an ALTER TABLE -- is a no-op
        // schema-state transition.
        if (statement.sql.starts_with("CREATE INDEX ") || statement.sql.starts_with("DROP INDEX "))
        {
            return true;
        }
        // Data-only migrations (backfills, corrective updates) do not change the
        // table set. They have already passed SQL-shape validation, so accept
        // them as no-op schema-state transitions.
        return is_data_only_statement(statement.sql);
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
    // The whole schema, tables then indexes. Every pre-1.0 migration was folded
    // into this one step (ADR-0224); migrations/001_initial_schema.sql records it
    // statement for statement, and from 1.0.0 neither may change.
    auto statements = std::vector<PreparedStatement>{};
    for (auto const& table : initial_schema_definitions())
    {
        // Core table definitions are allowlisted at compile time, so the
        // generated CREATE TABLE SQL is always valid.
        statements.push_back(make_create_table_statement(table).value());
    }
    for (auto const& index : initial_schema_indexes())
    {
        // Likewise for the registered indexes.
        statements.push_back(make_create_index_statement(index).value());
    }
    return {initial_schema_version, std::string{initial_schema_name}, std::move(statements),
            MigrationDirection::upgrade};
}

auto downgrade_initial_schema_migration() -> MigrationStep
{
    auto statements = std::vector<PreparedStatement>{};
    auto definitions = initial_schema_definitions();
    // Drop in reverse declaration order so dependent tables come down
    // before the ones they reference. Each table's indexes go with it.
    for (auto iterator = definitions.rbegin(); iterator != definitions.rend(); ++iterator)
    {
        // Core table names are allowlisted at compile time, so the generated
        // DROP TABLE SQL is always valid.
        statements.push_back(make_drop_table_statement(iterator->name).value());
    }
    return {0U, "drop_initial_schema", std::move(statements), MigrationDirection::downgrade};
}

// The next migration is v2: add its upgrade step here and its downgrade (to v1)
// at the front of the downgrade catalog, and leave v1 exactly as it is.
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
        log_diagnostic("plan.rejected", {
                                            {"current_version", std::to_string(plan.current_version), false},
                                            {"target_version",  std::to_string(plan.target_version),  false},
                                            {"reason",          validation.reason,                    false}
        });
        return {false, validation.reason, std::move(state)};
    }
    if (state.version != plan.current_version)
    {
        log_diagnostic("plan.rejected", {
                                            {"state_version",   std::to_string(state.version),                        false},
                                            {"current_version", std::to_string(plan.current_version),                 false},
                                            {"reason",          "schema state version does not match migration plan", false}
        });
        return {false, "schema state version does not match migration plan", std::move(state)};
    }
    for (auto const& step : plan.steps)
    {
        for (auto const& statement : step.statements)
        {
            if (!apply_statement_to_schema_state(state, statement))
            {
                log_diagnostic("step.failed",
                               {
                                   {"step_name", step.name,                                             false},
                                   {"version",   std::to_string(step.version),                          false},
                                   {"direction", std::string{migration_direction_name(step.direction)}, false},
                                   {"statement", statement.name,                                        false},
                                   {"reason",    "migration statement cannot update schema state",      false}
                });
                return {false, "migration statement cannot update schema state: " + statement.name, std::move(state)};
            }
        }
        log_diagnostic("step.applied",
                       {
                           {"step_name",  step.name,                                             false},
                           {"version",    std::to_string(step.version),                          false},
                           {"direction",  std::string{migration_direction_name(step.direction)}, false},
                           {"statements", std::to_string(step.statements.size()),                false}
        },
                       observability::LogEventSeverity::info);
        state.applied_migrations.push_back({step.version, step.name, step.direction});
        state.version = step.version;
    }
    log_diagnostic("plan.complete",
                   {
                       {"direction",       std::string{migration_direction_name(plan.direction)}, false},
                       {"current_version", std::to_string(plan.current_version),                  false},
                       {"target_version",  std::to_string(plan.target_version),                   false},
                       {"steps_applied",   std::to_string(plan.steps.size()),                     false}
    },
                   observability::LogEventSeverity::info);
    return {true, {}, std::move(state)};
}

auto schema_ledger_is_known(SchemaState const& state) -> MigrationValidationResult
{
    // A version number alone cannot tell this build's v1 from another build's:
    // every pre-1.0 build up to 0.12.46 wrote a v1 row too, followed by rows
    // for 25 migrations that no longer exist. So every upgrade row must name
    // the step this build has at that version.
    auto const catalog = upgrade_migration_catalog();
    for (auto const& record : state.applied_migrations)
    {
        if (record.direction != MigrationDirection::upgrade)
        {
            continue;
        }
        auto const step = std::ranges::find_if(catalog, [&record](MigrationStep const& known) {
            return known.version == record.version;
        });
        if (step == catalog.end() || step->name != record.name)
        {
            return {false, "schema ledger records a migration this build does not have: version " +
                               std::to_string(record.version) + " (" + record.name +
                               "); it was written by a newer build, or by a pre-1.0 build from before the "
                               "0.12.47 schema collapse, and this build cannot open it"};
        }
    }
    return {true, {}};
}

auto schema_state_is_compatible(SchemaState const& state) -> MigrationValidationResult
{
    if (auto known = schema_ledger_is_known(state); !known.valid)
    {
        return known;
    }
    if (state.version != current_schema_version())
    {
        return {false, "schema version is not compatible"};
    }
    if (!has_migration_record(state, current_schema_version(), MigrationDirection::upgrade))
    {
        return {false, "current schema migration is not recorded"};
    }
    for (auto const table : current_schema_tables())
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
    return "schema deploys at v1 in its final shape; the only downgrade drops it, exists for completeness, "
           "and remains operator-controlled, paired with backup/restore validation";
}

} // namespace merovingian::database
