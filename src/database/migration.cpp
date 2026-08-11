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
    // The schema deploys at version 1. Later numbered migrations bring the
    // store up to current_schema_version(). Fresh installs create the v1 shape
    // first so that the same migration chain upgrades both new and existing
    // databases.
    auto statements = std::vector<PreparedStatement>{};
    for (auto const& table : initial_schema_definitions())
    {
        // Core table definitions are allowlisted at compile time, so the
        // generated CREATE TABLE SQL is always valid.
        statements.push_back(make_create_table_statement(table).value());
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
        // Core table names are allowlisted at compile time, so the generated
        // DROP TABLE SQL is always valid.
        statements.push_back(make_drop_table_statement(iterator->name).value());
    }
    return {0U, "drop_initial_schema", std::move(statements), MigrationDirection::downgrade};
}

[[nodiscard]] auto upgrade_sync_stream_watermark_migration() -> MigrationStep
{
    auto statements = std::vector<PreparedStatement>{};
    statements.push_back(make_create_table_statement(schema_table_definition("sync_stream_watermark").value()).value());
    return {2U, "sync_stream_watermark", std::move(statements), MigrationDirection::upgrade};
}

[[nodiscard]] auto upgrade_event_stream_watermark_migration() -> MigrationStep
{
    auto statements = std::vector<PreparedStatement>{};
    statements.push_back(
        make_create_table_statement(schema_table_definition("event_stream_watermark").value()).value());
    return {3U, "event_stream_watermark", std::move(statements), MigrationDirection::upgrade};
}

[[nodiscard]] auto upgrade_state_transitions_migration() -> MigrationStep
{
    auto statements = std::vector<PreparedStatement>{};
    statements.push_back(make_create_table_statement(schema_table_definition("state_transitions").value()).value());
    return {4U, "state_transitions", std::move(statements), MigrationDirection::upgrade};
}

[[nodiscard]] auto upgrade_backfill_state_transitions_migration() -> MigrationStep
{
    auto statements = std::vector<PreparedStatement>{};
    // Populate state_transitions with one row per existing current_state entry so
    // already-created rooms do not silently lack transition history. Previous
    // event IDs are left empty because the old deployment did not record them;
    // only future replacements will have an accurate predecessor.
    statements.push_back(
        PreparedStatement{"backfill_state_transitions",
                          "INSERT INTO state_transitions (room_id, event_type, state_key, event_id, previous_event_id) "
                          "SELECT c.room_id, c.event_type, c.state_key, c.event_id, '' FROM current_state c "
                          "LEFT JOIN state_transitions t ON t.room_id = c.room_id AND t.event_type = c.event_type AND "
                          "t.state_key = c.state_key AND t.event_id = c.event_id "
                          "WHERE t.room_id IS NULL",
                          {}});
    return {5U, "backfill_state_transitions", std::move(statements), MigrationDirection::upgrade};
}

[[nodiscard]] auto upgrade_account_threepids_migration() -> MigrationStep
{
    auto statements = std::vector<PreparedStatement>{};
    statements.push_back(make_create_table_statement(schema_table_definition("account_threepids").value()).value());
    return {6U, "account_threepids", std::move(statements), MigrationDirection::upgrade};
}

// v7: add the IS validation pair (`client_secret`, `sid`) to account_threepids.
// Populated only for 3PIDs bound via a remote identity server, so a later unbind
// can drive IS auth mode 2 (sid + client_secret) without HS-signed requests. The
// base table is created at v6; this step ALTERs the columns onto it so the v6
// migration stays historically intact and fresh installs (which run every
// upgrade step in order) end at the same v7 shape.
[[nodiscard]] auto upgrade_account_threepids_columns_migration() -> MigrationStep
{
    auto statements = std::vector<PreparedStatement>{};
    statements.push_back(
        PreparedStatement{"add_client_secret_column",
                          "ALTER TABLE account_threepids ADD COLUMN client_secret TEXT NOT NULL DEFAULT ''",
                          {}});
    statements.push_back(PreparedStatement{
        "add_sid_column", "ALTER TABLE account_threepids ADD COLUMN sid TEXT NOT NULL DEFAULT ''", {}});
    return {7U, "account_threepids_columns", std::move(statements), MigrationDirection::upgrade};
}

// v8: durable pushers table (Matrix v1.19 CS API Push Notifications module).
// Persists the pusher fields the spec defines — pushkey, kind, app_id,
// app_display_name, device_display_name, profile_tag, lang, and the `data`
// dictionary's `url`/`format` keys — keyed on (user_id, app_id, pushkey) per
// the spec's "same app_id and pushkey for this user is updated" rule.
[[nodiscard]] auto upgrade_pushers_migration() -> MigrationStep
{
    auto statements = std::vector<PreparedStatement>{};
    statements.push_back(make_create_table_statement(schema_table_definition("pushers").value()).value());
    return {8U, "pushers", std::move(statements), MigrationDirection::upgrade};
}

// v9: durable notification history for `GET /_matrix/client/v3/notifications`
// (Matrix v1.19 CS API §push-notifications). Recorded whenever push rule
// evaluation resolves `notify: true` for a local recipient -- independent of
// whether that recipient has a registered pusher or `server.push.enabled` is
// set (see room_service.cpp's build_pending_push_deliveries), so a user with
// push notifications turned off still sees their notification history.
// `stream_ordering` mirrors the triggering event's stream position and
// doubles as this table's pagination key, exactly like `events.stream_
// ordering` already does for GET /messages. Retention: pruned per-user at
// write time (see database::store_notification), so the table cannot grow
// without bound.
[[nodiscard]] auto upgrade_notifications_migration() -> MigrationStep
{
    auto statements = std::vector<PreparedStatement>{};
    statements.push_back(make_create_table_statement(schema_table_definition("notifications").value()).value());
    return {9U, "notifications", std::move(statements), MigrationDirection::upgrade};
}

// v10: durable OpenID token store for `POST
// /_matrix/client/v3/user/{userId}/openid/request_token` (Matrix v1.19 CS
// API §OpenID). Deliberately a table of its own, never the `access_tokens`
// table: an OpenID token is a narrow, short-lived credential that is only
// ever redeemed by `GET /_matrix/federation/v1/openid/userinfo` (SS API
// §OpenID) and must never be usable to authenticate an ordinary
// client-server request (see docs/threat-model.md). Every row has a finite
// `expires_at`; expired rows are pruned at write time (see
// database::store_openid_token), so the table cannot grow without bound.
[[nodiscard]] auto upgrade_openid_tokens_migration() -> MigrationStep
{
    auto statements = std::vector<PreparedStatement>{};
    statements.push_back(make_create_table_statement(schema_table_definition("openid_tokens").value()).value());
    return {10U, "openid_tokens", std::move(statements), MigrationDirection::upgrade};
}

auto upgrade_migration_catalog() -> std::vector<MigrationStep>
{
    return {initial_schema_migration(),
            upgrade_sync_stream_watermark_migration(),
            upgrade_event_stream_watermark_migration(),
            upgrade_state_transitions_migration(),
            upgrade_backfill_state_transitions_migration(),
            upgrade_account_threepids_migration(),
            upgrade_account_threepids_columns_migration(),
            upgrade_pushers_migration(),
            upgrade_notifications_migration(),
            upgrade_openid_tokens_migration()};
}

[[nodiscard]] auto downgrade_backfill_state_transitions_migration() -> MigrationStep
{
    auto statements = std::vector<PreparedStatement>{};
    // Undo the v5 backfill. The state_transitions table itself is owned by the v4
    // migration and is dropped by the v4 downgrade.
    statements.push_back(PreparedStatement{"clear_state_transitions", "DELETE FROM state_transitions", {}});
    return {4U, "drop_backfill_state_transitions", std::move(statements), MigrationDirection::downgrade};
}

[[nodiscard]] auto downgrade_account_threepids_migration() -> MigrationStep
{
    auto statements = std::vector<PreparedStatement>{};
    statements.push_back(make_drop_table_statement("account_threepids").value());
    return {5U, "drop_account_threepids", std::move(statements), MigrationDirection::downgrade};
}

// v7 → v6: drop the IS validation pair before the v6 → v5 table-drop. The
// downgrade plan walks one version at a time, so this step (target v6) is
// selected before drop_account_threepids (target v5) when downgrading from v7.
[[nodiscard]] auto downgrade_account_threepids_columns_migration() -> MigrationStep
{
    auto statements = std::vector<PreparedStatement>{};
    statements.push_back(PreparedStatement{"drop_sid_column", "ALTER TABLE account_threepids DROP COLUMN sid", {}});
    statements.push_back(
        PreparedStatement{"drop_client_secret_column", "ALTER TABLE account_threepids DROP COLUMN client_secret", {}});
    return {6U, "drop_account_threepids_columns", std::move(statements), MigrationDirection::downgrade};
}

// v8 -> v7: drop the pushers table.
[[nodiscard]] auto downgrade_pushers_migration() -> MigrationStep
{
    auto statements = std::vector<PreparedStatement>{};
    statements.push_back(make_drop_table_statement("pushers").value());
    return {7U, "drop_pushers", std::move(statements), MigrationDirection::downgrade};
}

// v9 -> v8: drop the notifications table.
[[nodiscard]] auto downgrade_notifications_migration() -> MigrationStep
{
    auto statements = std::vector<PreparedStatement>{};
    statements.push_back(make_drop_table_statement("notifications").value());
    return {8U, "drop_notifications", std::move(statements), MigrationDirection::downgrade};
}

// v10 -> v9: drop the openid_tokens table.
[[nodiscard]] auto downgrade_openid_tokens_migration() -> MigrationStep
{
    auto statements = std::vector<PreparedStatement>{};
    statements.push_back(make_drop_table_statement("openid_tokens").value());
    return {9U, "drop_openid_tokens", std::move(statements), MigrationDirection::downgrade};
}

[[nodiscard]] auto downgrade_sync_stream_watermark_migration() -> MigrationStep
{
    auto statements = std::vector<PreparedStatement>{};
    statements.push_back(make_drop_table_statement("sync_stream_watermark").value());
    return {1U, "drop_sync_stream_watermark", std::move(statements), MigrationDirection::downgrade};
}

[[nodiscard]] auto downgrade_event_stream_watermark_migration() -> MigrationStep
{
    auto statements = std::vector<PreparedStatement>{};
    statements.push_back(make_drop_table_statement("event_stream_watermark").value());
    return {2U, "drop_event_stream_watermark", std::move(statements), MigrationDirection::downgrade};
}

[[nodiscard]] auto downgrade_state_transitions_migration() -> MigrationStep
{
    auto statements = std::vector<PreparedStatement>{};
    statements.push_back(make_drop_table_statement("state_transitions").value());
    return {3U, "drop_state_transitions", std::move(statements), MigrationDirection::downgrade};
}

auto downgrade_migration_catalog() -> std::vector<MigrationStep>
{
    return {downgrade_openid_tokens_migration(),
            downgrade_notifications_migration(),
            downgrade_pushers_migration(),
            downgrade_account_threepids_columns_migration(),
            downgrade_account_threepids_migration(),
            downgrade_backfill_state_transitions_migration(),
            downgrade_state_transitions_migration(),
            downgrade_event_stream_watermark_migration(),
            downgrade_sync_stream_watermark_migration(),
            downgrade_initial_schema_migration()};
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
    return "schema deploys at v1 in its final shape; downgrade plans exist for completeness "
           "and remain operator-controlled, paired with backup/restore validation";
}

} // namespace merovingian::database
