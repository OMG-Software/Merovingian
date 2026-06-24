// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/database/schema.hpp"
#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"

#include <cstdint>
#include <filesystem>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

#include <sqlite3.h>

namespace merovingian::database
{
namespace
{

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields) -> void
    {
        LOG_DEBUG(observability::diagnostic_log_summary("sqlite_store", event, std::move(fields)));
    }

    struct SqliteConnectionDeleter final
    {
        auto operator()(sqlite3* connection) const noexcept -> void
        {
            sqlite3_close(connection);
        }
    };

    using SqliteConnection = std::unique_ptr<sqlite3, SqliteConnectionDeleter>;

    struct SqliteStatementDeleter final
    {
        auto operator()(sqlite3_stmt* statement) const noexcept -> void
        {
            sqlite3_finalize(statement);
        }
    };

    using SqliteStatement = std::unique_ptr<sqlite3_stmt, SqliteStatementDeleter>;

    [[nodiscard]] auto execute_sql(sqlite3& connection, std::string const& sql) -> bool;

    [[nodiscard]] auto parse_invite_state_events_json(std::string_view json) -> std::vector<std::string>
    {
        auto const parsed = canonicaljson::parse_lossless(json);
        if (parsed.error != canonicaljson::ParseError::none)
        {
            return {};
        }
        auto const* events = std::get_if<canonicaljson::Array>(&parsed.value.storage());
        if (events == nullptr)
        {
            return {};
        }
        auto result = std::vector<std::string>{};
        result.reserve(events->size());
        for (auto const& event : *events)
        {
            auto serialized = canonicaljson::serialize_canonical(event);
            if (serialized.error != canonicaljson::CanonicalJsonError::none)
            {
                return {};
            }
            result.push_back(std::move(serialized.output));
        }
        return result;
    }

    class SqliteTransaction final
    {
    public:
        explicit SqliteTransaction(sqlite3& connection)
            : connection_{connection}
        {
            active_ = execute_sql(connection_, "BEGIN IMMEDIATE");
        }

        SqliteTransaction(SqliteTransaction const& other) = delete;
        auto operator=(SqliteTransaction const& other) -> SqliteTransaction& = delete;
        SqliteTransaction(SqliteTransaction&& other) noexcept = delete;
        auto operator=(SqliteTransaction&& other) noexcept -> SqliteTransaction& = delete;

        ~SqliteTransaction()
        {
            if (active_)
            {
                std::ignore = execute_sql(connection_, "ROLLBACK");
            }
        }

        [[nodiscard]] auto active() const noexcept -> bool
        {
            return active_;
        }

        [[nodiscard]] auto commit() noexcept -> bool
        {
            if (!active_ || !execute_sql(connection_, "COMMIT"))
            {
                return false;
            }
            active_ = false;
            return true;
        }

    private:
        sqlite3& connection_;
        bool active_{false};
    };

    [[nodiscard]] auto sqlite_transient_destructor() noexcept -> sqlite3_destructor_type
    {
        // SQLite documents -1 as the special destructor value that copies the bound data immediately.
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        return reinterpret_cast<sqlite3_destructor_type>(-1);
    }

    [[nodiscard]] auto open_sqlite_connection(std::string const& path) -> std::optional<SqliteConnection>
    {
        try
        {
            auto const parent = std::filesystem::path{path}.parent_path();
            if (!parent.empty())
            {
                std::filesystem::create_directories(parent);
            }
        }
        catch (std::filesystem::filesystem_error const&)
        {
            return std::nullopt;
        }

        auto* raw = static_cast<sqlite3*>(nullptr);
        if (sqlite3_open_v2(path.c_str(), &raw, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                            nullptr) != SQLITE_OK)
        {
            sqlite3_close(raw);
            return std::nullopt;
        }

        auto constexpr busy_timeout_ms = 5000;
        if (sqlite3_busy_timeout(raw, busy_timeout_ms) != SQLITE_OK)
        {
            sqlite3_close(raw);
            return std::nullopt;
        }

        return SqliteConnection{raw};
    }

    [[nodiscard]] auto execute_sql(sqlite3& connection, std::string const& sql) -> bool
    {
        auto* error = static_cast<char*>(nullptr);
        auto const ok = sqlite3_exec(&connection, sql.c_str(), nullptr, nullptr, &error) == SQLITE_OK;
        sqlite3_free(error);
        return ok;
    }

    [[nodiscard]] auto create_table_if_missing_sql(SchemaTableDefinition const& table) -> std::optional<std::string>
    {
        // Only core tables may be materialised by the bootstrap path; unknown
        // names fail closed rather than being concatenated into DDL.
        if (!schema_table_is_core(table.name))
        {
            return std::nullopt;
        }

        auto quoted = quote_sqlite_identifier(table.name);
        if (!quoted.has_value())
        {
            return std::nullopt;
        }

        return "CREATE TABLE IF NOT EXISTS " + std::move(*quoted) + " (" + std::string{table.columns_sql} + ")";
    }

    [[nodiscard]] auto prepare(sqlite3& connection, std::string const& sql) -> std::optional<SqliteStatement>
    {
        auto* raw = static_cast<sqlite3_stmt*>(nullptr);
        if (sqlite3_prepare_v2(&connection, sql.c_str(), -1, &raw, nullptr) != SQLITE_OK)
        {
            return std::nullopt;
        }
        return SqliteStatement{raw};
    }

    [[nodiscard]] auto column_text(sqlite3_stmt& statement, int column) -> std::string
    {
        auto const* value = sqlite3_column_text(&statement, column);
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        return value == nullptr ? std::string{} : std::string{reinterpret_cast<char const*>(value)};
    }

    [[nodiscard]] auto text_is_true(std::string_view value) noexcept -> bool
    {
        return value == "true";
    }

    [[nodiscard]] auto parse_u64(std::string_view value) noexcept -> std::uint64_t
    {
        auto result = std::uint64_t{0U};
        for (auto const character : value)
        {
            if (character < '0' || character > '9')
            {
                return 0U;
            }
            result = (result * 10U) + static_cast<std::uint64_t>(character - '0');
        }
        return result;
    }

    [[nodiscard]] auto load_table_names(sqlite3& connection) -> std::vector<std::string>
    {
        auto statement = prepare(connection, "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name");
        auto tables = std::vector<std::string>{};
        if (!statement.has_value())
        {
            return tables;
        }
        while (sqlite3_step(statement->get()) == SQLITE_ROW)
        {
            tables.push_back(column_text(*statement->get(), 0));
        }
        return tables;
    }

    [[nodiscard]] auto direction_from_text(std::string_view value) noexcept -> MigrationDirection
    {
        return value == "downgrade" ? MigrationDirection::downgrade : MigrationDirection::upgrade;
    }

    [[nodiscard]] auto load_schema_state(sqlite3& connection) -> SchemaState
    {
        auto state = SchemaState{};
        state.tables = load_table_names(connection);
        auto statement = prepare(connection, "SELECT version, name, direction FROM schema_migrations ORDER BY version");
        if (!statement.has_value())
        {
            return state;
        }
        while (sqlite3_step(statement->get()) == SQLITE_ROW)
        {
            auto const version = static_cast<std::uint32_t>(parse_u64(column_text(*statement->get(), 0)));
            state.applied_migrations.push_back(
                {version, column_text(*statement->get(), 1), direction_from_text(column_text(*statement->get(), 2))});
            if (version > state.version)
            {
                state.version = version;
            }
        }
        return state;
    }

    auto initialize_current_schema(sqlite3& connection) -> bool
    {
        // Wrap the entire bootstrap in one transaction so that a failure
        // after any CREATE TABLE leaves no partial schema or ledger row.
        auto transaction = SqliteTransaction{connection};
        if (!transaction.active())
        {
            return false;
        }

        for (auto const& table : initial_schema_definitions())
        {
            auto const sql = create_table_if_missing_sql(table);
            if (!sql.has_value() || !execute_sql(connection, *sql))
            {
                return false;
            }
        }

        // The schema lands at v1 in its final shape — there are no historic
        // database deployments to upgrade, so only the initial migration
        // record needs to be present.
        // Bootstrap records only the initial schema row. Runtime startup can
        // then apply newer numbered migrations against the freshly created
        // tables when current_schema_version() is greater than 1.
        if (!execute_sql(connection,
                         "INSERT OR IGNORE INTO schema_migrations VALUES ('1', 'initial_schema', 'upgrade')"))
        {
            return false;
        }

        return transaction.commit();
    }

    auto apply_pending_migrations(sqlite3& connection, SchemaState state) -> std::optional<SchemaState>
    {
        auto const plan = migration_plan_for(state);
        auto const validation = migration_plan_is_valid(plan);
        if (!validation.valid)
        {
            return std::nullopt;
        }
        for (auto const& step : plan.steps)
        {
            // Each migration step is atomic: all of its statements plus the
            // ledger-row insert succeed together or are rolled back together.
            auto transaction = SqliteTransaction{connection};
            if (!transaction.active())
            {
                return std::nullopt;
            }

            for (auto const& statement : step.statements)
            {
                if (!execute_sql(connection, statement.sql))
                {
                    return std::nullopt;
                }
            }
            // C3: switch the schema_migrations INSERT to a bound
            // PreparedStatement instead of string concatenation. The
            // values pass through SQLite's parameter binding (which
            // handles quoting, NUL bytes, and binary safely), matching
            // the boundary used by the rest of the database layer.
            auto record_statement = prepare(connection, "INSERT OR IGNORE INTO schema_migrations VALUES (?1, ?2, ?3)");
            if (!record_statement.has_value())
            {
                return std::nullopt;
            }
            auto& record_handle = *record_statement->get();
            auto const bind_result =
                sqlite3_bind_int64(&record_handle, 1, static_cast<sqlite3_int64>(step.version)) == SQLITE_OK &&
                sqlite3_bind_text(&record_handle, 2, step.name.c_str(), static_cast<int>(step.name.size()),
                                  sqlite_transient_destructor()) == SQLITE_OK &&
                sqlite3_bind_text(&record_handle, 3, migration_direction_name(step.direction).data(),
                                  static_cast<int>(migration_direction_name(step.direction).size()),
                                  sqlite_transient_destructor()) == SQLITE_OK;
            if (!bind_result)
            {
                return std::nullopt;
            }
            if (sqlite3_step(&record_handle) != SQLITE_DONE)
            {
                return std::nullopt;
            }
            sqlite3_reset(&record_handle);

            if (!transaction.commit())
            {
                return std::nullopt;
            }
        }
        auto applied = apply_migration_plan(std::move(state), plan);
        if (!applied.ok)
        {
            return std::nullopt;
        }
        return std::move(applied.state);
    }

    template <typename RowLoader>
    auto load_rows(sqlite3& connection, std::string const& sql, RowLoader load_row) -> bool
    {
        auto statement = prepare(connection, sql);
        if (!statement.has_value())
        {
            return false;
        }
        auto step = int{SQLITE_ROW};
        while ((step = sqlite3_step(statement->get())) == SQLITE_ROW)
        {
            load_row(*statement->get());
        }
        return step == SQLITE_DONE;
    }

    auto load_persistent_rows(sqlite3& connection, PersistentStore& store) -> bool
    {
        return load_rows(connection, "SELECT user_id, password_hash, locked, suspended, admin FROM users",
                         [&store](sqlite3_stmt& row) {
                             store.users.push_back(
                                 {column_text(row, 0), column_text(row, 1), text_is_true(column_text(row, 2)),
                                  text_is_true(column_text(row, 3)), text_is_true(column_text(row, 4))});
                         }) &&
               load_rows(connection, "SELECT user_id, device_id, display_name FROM devices",
                         [&store](sqlite3_stmt& row) {
                             store.devices.push_back({column_text(row, 0), column_text(row, 1), column_text(row, 2)});
                         }) &&
               load_rows(connection, "SELECT user_id, device_id, token_hash, revoked, expires_at FROM access_tokens",
                         [&store](sqlite3_stmt& row) {
                             store.access_tokens.push_back({column_text(row, 0), column_text(row, 1),
                                                            column_text(row, 2), text_is_true(column_text(row, 3)),
                                                            parse_expires_at(column_text(row, 4))});
                         }) &&
               load_rows(connection, "SELECT user_id, device_id, token_hash, revoked, expires_at FROM refresh_tokens",
                         [&store](sqlite3_stmt& row) {
                             store.refresh_tokens.push_back({column_text(row, 0), column_text(row, 1),
                                                             column_text(row, 2), text_is_true(column_text(row, 3)),
                                                             parse_expires_at(column_text(row, 4))});
                         }) &&
               load_rows(connection,
                         "SELECT server_name, key_id, public_key, valid_until_ts, secret_key FROM server_signing_keys",
                         [&store](sqlite3_stmt& row) {
                             store.server_signing_keys.push_back({column_text(row, 0), column_text(row, 1),
                                                                  column_text(row, 2), parse_u64(column_text(row, 3)),
                                                                  column_text(row, 4)});
                         }) &&
               load_rows(connection,
                         "SELECT server_name, state, retry_after_ts, last_success_ts, consecutive_failures FROM "
                         "federation_destinations",
                         [&store](sqlite3_stmt& row) {
                             store.federation_destinations.push_back(
                                 {column_text(row, 0), column_text(row, 1), parse_u64(column_text(row, 2)),
                                  parse_u64(column_text(row, 3)),
                                  static_cast<std::uint32_t>(parse_u64(column_text(row, 4)))});
                         }) &&
               load_rows(connection,
                         "SELECT transaction_id, server_name, method, target, origin, origin_server_ts, body, "
                         "retry_count, next_retry_ts FROM federation_transactions",
                         [&store](sqlite3_stmt& row) {
                             store.federation_transactions.push_back(
                                 {column_text(row, 0), column_text(row, 1), column_text(row, 2), column_text(row, 3),
                                  column_text(row, 4), column_text(row, 5), column_text(row, 6),
                                  static_cast<std::uint32_t>(parse_u64(column_text(row, 7))),
                                  parse_u64(column_text(row, 8))});
                         }) &&
               load_rows(connection, "SELECT room_id, creator_user_id FROM rooms",
                         [&store](sqlite3_stmt& row) {
                             store.rooms.push_back({column_text(row, 0), column_text(row, 1)});
                         }) &&
               load_rows(connection, "SELECT room_id, user_id, membership, stream_ordering FROM membership",
                         [&store](sqlite3_stmt& row) {
                             store.memberships.push_back({column_text(row, 0), column_text(row, 1), column_text(row, 2),
                                                          parse_u64(column_text(row, 3))});
                         }) &&
               load_rows(connection,
                         "SELECT room_id, user_id, sender_user_id, event_id, signed_event_json, invite_state_json, "
                         "stream_ordering FROM invites",
                         [&store](sqlite3_stmt& row) {
                             store.invites.push_back({column_text(row, 0), column_text(row, 1), column_text(row, 2),
                                                      column_text(row, 3), column_text(row, 4),
                                                      parse_invite_state_events_json(column_text(row, 5)),
                                                      parse_u64(column_text(row, 6))});
                         }) &&
               load_rows(connection,
                         "SELECT event_id, room_id, sender_user_id, json, depth, stream_ordering FROM events",
                         [&store](sqlite3_stmt& row) {
                             store.events.push_back({column_text(row, 0), column_text(row, 1), column_text(row, 2),
                                                     column_text(row, 3), parse_u64(column_text(row, 4)),
                                                     parse_u64(column_text(row, 5))});
                         }) &&
               load_rows(connection, "SELECT event_id, prev_event_id FROM event_edges",
                         [&store](sqlite3_stmt& row) {
                             store.event_edges.push_back({column_text(row, 0), column_text(row, 1)});
                         }) &&
               load_rows(connection, "SELECT event_id, auth_event_id FROM event_auth",
                         [&store](sqlite3_stmt& row) {
                             store.event_auth.push_back({column_text(row, 0), column_text(row, 1)});
                         }) &&
               load_rows(connection, "SELECT event_id, server_name, key_id, signature FROM event_signatures",
                         [&store](sqlite3_stmt& row) {
                             store.event_signatures.push_back(
                                 {column_text(row, 0), column_text(row, 1), column_text(row, 2), column_text(row, 3)});
                         }) &&
               load_rows(connection, "SELECT room_id, event_type, state_key, event_id FROM current_state",
                         [&store](sqlite3_stmt& row) {
                             store.state.push_back(
                                 {column_text(row, 0), column_text(row, 1), column_text(row, 2), column_text(row, 3)});
                         }) &&
               load_rows(connection, "SELECT user_id, device_id, json FROM device_keys",
                         [&store](sqlite3_stmt& row) {
                             store.device_keys.push_back(
                                 {column_text(row, 0), column_text(row, 1), column_text(row, 2)});
                         }) &&
               load_rows(connection, "SELECT user_id, device_id, key_id, json FROM one_time_keys",
                         [&store](sqlite3_stmt& row) {
                             store.one_time_keys.push_back(
                                 {column_text(row, 0), column_text(row, 1), column_text(row, 2), column_text(row, 3)});
                         }) &&
               load_rows(connection, "SELECT user_id, device_id, key_id, json FROM fallback_keys",
                         [&store](sqlite3_stmt& row) {
                             store.fallback_keys.push_back(
                                 {column_text(row, 0), column_text(row, 1), column_text(row, 2), column_text(row, 3)});
                         }) &&
               load_rows(connection, "SELECT user_id, key_type, json FROM cross_signing_keys",
                         [&store](sqlite3_stmt& row) {
                             store.cross_signing_keys.push_back(
                                 {column_text(row, 0), column_text(row, 1), column_text(row, 2)});
                         }) &&
               load_rows(connection,
                         "SELECT signer_user_id, target_user_id, target_device_id, json FROM key_signatures",
                         [&store](sqlite3_stmt& row) {
                             store.key_signatures.push_back(
                                 {column_text(row, 0), column_text(row, 1), column_text(row, 2), column_text(row, 3)});
                         }) &&
               load_rows(connection, "SELECT user_id, version, json FROM key_backup_versions",
                         [&store](sqlite3_stmt& row) {
                             store.key_backup_versions.push_back(
                                 {column_text(row, 0), column_text(row, 1), column_text(row, 2)});
                         }) &&
               load_rows(connection, "SELECT user_id, version, room_id, session_id, json FROM key_backup_sessions",
                         [&store](sqlite3_stmt& row) {
                             store.key_backup_sessions.push_back({column_text(row, 0), column_text(row, 1),
                                                                  column_text(row, 2), column_text(row, 3),
                                                                  column_text(row, 4)});
                         }) &&
               load_rows(
                   connection,
                   "SELECT media_id, owner_user_id, content_type, size_bytes, hash_algorithm, digest, quarantined, "
                   "removed FROM media",
                   [&store](sqlite3_stmt& row) {
                       store.local_media.push_back({column_text(row, 0), column_text(row, 1), column_text(row, 2),
                                                    parse_u64(column_text(row, 3)), column_text(row, 4),
                                                    column_text(row, 5), text_is_true(column_text(row, 6)),
                                                    text_is_true(column_text(row, 7))});
                   }) &&
               load_rows(connection,
                         "SELECT storage_id, hash_algorithm, digest, size_bytes, bytes, ref_count FROM media_blobs",
                         [&store](sqlite3_stmt& row) {
                             store.media_blobs.push_back({column_text(row, 0), column_text(row, 1), column_text(row, 2),
                                                          parse_u64(column_text(row, 3)), column_text(row, 4),
                                                          parse_u64(column_text(row, 5))});
                         }) &&
               load_rows(connection,
                         "SELECT server_name, media_id, content_type, size_bytes, quarantined FROM "
                         "remote_media",
                         [&store](sqlite3_stmt& row) {
                             store.remote_media.push_back({column_text(row, 0), column_text(row, 1),
                                                           column_text(row, 2), parse_u64(column_text(row, 3)),
                                                           text_is_true(column_text(row, 4))});
                         }) &&
               load_rows(connection, "SELECT category, event_type, actor, target, reason FROM audit_log",
                         [&store](sqlite3_stmt& row) {
                             store.audit_log.push_back({column_text(row, 0), column_text(row, 1), column_text(row, 2),
                                                        column_text(row, 3), column_text(row, 4)});
                         }) &&
               load_rows(connection, "SELECT admin_user_id, action, target FROM admin_actions",
                         [&store](sqlite3_stmt& row) {
                             store.admin_actions.push_back(
                                 {column_text(row, 0), column_text(row, 1), column_text(row, 2)});
                         }) &&
               load_rows(connection, "SELECT rule_id, scope, entity, action, reason FROM policy_rules ORDER BY rule_id",
                         [&store](sqlite3_stmt& row) {
                             store.policy_rules.push_back({column_text(row, 0), column_text(row, 1),
                                                           column_text(row, 2), column_text(row, 3),
                                                           column_text(row, 4)});
                         }) &&
               load_rows(connection, "SELECT user_id, event_type, json, stream_id FROM account_data ORDER BY stream_id",
                         [&store](sqlite3_stmt& row) {
                             auto entry = PersistentAccountData{};
                             entry.user_id = column_text(row, 0);
                             entry.event_type = column_text(row, 1);
                             entry.content_json = column_text(row, 2);
                             entry.stream_id = parse_u64(column_text(row, 3));
                             store.account_data.push_back(std::move(entry));
                         }) &&
               load_rows(connection,
                         "SELECT user_id, room_id, event_type, stream_id, json FROM room_account_data ORDER "
                         "BY stream_id",
                         [&store](sqlite3_stmt& row) {
                             auto entry = PersistentAccountData{};
                             entry.user_id = column_text(row, 0);
                             entry.room_id = column_text(row, 1);
                             entry.event_type = column_text(row, 2);
                             entry.stream_id = parse_u64(column_text(row, 3));
                             entry.content_json = column_text(row, 4);
                             store.account_data.push_back(std::move(entry));
                         }) &&
               load_rows(connection,
                         "SELECT stream_id, sender_user_id, target_user_id, target_device_id, message_type, "
                         "content FROM to_device_messages ORDER BY stream_id",
                         [&store](sqlite3_stmt& row) {
                             auto entry = PersistentToDeviceMessage{};
                             entry.stream_id = parse_u64(column_text(row, 0));
                             entry.sender_user_id = column_text(row, 1);
                             entry.target_user_id = column_text(row, 2);
                             entry.target_device_id = column_text(row, 3);
                             entry.message_type = column_text(row, 4);
                             entry.content_json = column_text(row, 5);
                             store.to_device_messages.push_back(std::move(entry));
                         }) &&
               load_rows(connection,
                         "SELECT stream_id, observer_user_id, subject_user_id, change_type FROM "
                         "device_list_changes ORDER BY stream_id",
                         [&store](sqlite3_stmt& row) {
                             auto entry = PersistentDeviceListChange{};
                             entry.stream_id = parse_u64(column_text(row, 0));
                             entry.observer_user_id = column_text(row, 1);
                             entry.subject_user_id = column_text(row, 2);
                             entry.change_type = column_text(row, 3);
                             store.device_list_changes.push_back(std::move(entry));
                         }) &&
               load_rows(connection,
                         "SELECT user_id, stream_id, presence, status_msg, last_active_ago, currently_active "
                         "FROM presence_state ORDER BY stream_id",
                         [&store](sqlite3_stmt& row) {
                             auto entry = PersistentPresence{};
                             entry.user_id = column_text(row, 0);
                             entry.stream_id = parse_u64(column_text(row, 1));
                             entry.presence = column_text(row, 2);
                             entry.status_msg = column_text(row, 3);
                             entry.last_active_ago = static_cast<std::int64_t>(parse_u64(column_text(row, 4)));
                             entry.currently_active = text_is_true(column_text(row, 5));
                             store.presence_states.push_back(std::move(entry));
                         }) &&
               load_rows(connection, "SELECT user_id, filter_id, json FROM filters",
                         [&store](sqlite3_stmt& row) {
                             store.filters.push_back({column_text(row, 0), column_text(row, 1), column_text(row, 2)});
                         }) &&
               load_rows(connection, "SELECT user_id, displayname, avatar_url FROM profiles",
                         [&store](sqlite3_stmt& row) {
                             store.profiles.push_back({column_text(row, 0), column_text(row, 1), column_text(row, 2)});
                         }) &&
               load_rows(connection, "SELECT room_alias, room_id FROM room_aliases ORDER BY room_alias",
                         [&store](sqlite3_stmt& row) {
                             store.room_aliases.push_back({column_text(row, 0), column_text(row, 1)});
                         }) &&
               load_rows(connection, "SELECT user_id, room_id, event_type, txn_id, event_id FROM client_txn_ids",
                         [&store](sqlite3_stmt& row) {
                             store.client_txn_ids.push_back({column_text(row, 0), column_text(row, 1),
                                                             column_text(row, 2), column_text(row, 3),
                                                             column_text(row, 4)});
                         }) &&
               load_rows(connection, "SELECT watermark FROM sync_stream_watermark", [&store](sqlite3_stmt& row) {
                   store.next_sync_stream_id = parse_u64(column_text(row, 0));
               });
    }

    [[nodiscard]] auto bind_statement_parameters(sqlite3_stmt& statement, PreparedStatement const& prepared) -> bool
    {
        for (auto index = std::size_t{0U}; index < prepared.parameters.size(); ++index)
        {
            auto const name = "$" + std::to_string(index + 1U);
            auto bind_index = sqlite3_bind_parameter_index(&statement, name.c_str());
            if (bind_index == 0)
            {
                bind_index = static_cast<int>(index + 1U);
            }
            auto const& value = prepared.parameters[index].value;
            if (value.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()))
            {
                return false;
            }
            auto const value_size = static_cast<int>(value.size());
            // B5 contract: sqlite_transient_destructor() (the -1 sentinel)
            // tells SQLite to copy the bound buffer immediately, so the
            // std::string we're passing a c_str() of can be a stack-local
            // that goes out of scope before sqlite3_step returns. Do not
            // switch to SQLITE_STATIC without ensuring the parameter view
            // outlives the step call — otherwise we'd be reading freed
            // memory.
            if (sqlite3_bind_text(&statement, bind_index, value.c_str(), value_size, sqlite_transient_destructor()) !=
                SQLITE_OK)
            {
                return false;
            }
        }
        return true;
    }

    [[nodiscard]] auto execute_prepared(sqlite3& connection, PreparedStatement const& prepared) -> bool
    {
        auto statement = prepare(connection, prepared.sql);
        if (!statement.has_value())
        {
            return false;
        }
        return bind_statement_parameters(*statement->get(), prepared) && sqlite3_step(statement->get()) == SQLITE_DONE;
    }

    [[nodiscard]] auto execute_transaction(sqlite3& connection, std::vector<PreparedStatement> const& statements)
        -> bool
    {
        auto transaction = SqliteTransaction{connection};
        if (!transaction.active())
        {
            return false;
        }
        for (auto const& statement : statements)
        {
            if (!execute_prepared(connection, statement))
            {
                return false;
            }
        }
        return transaction.commit();
    }

} // namespace

auto open_sqlite_persistent_store(std::string const& path) -> PersistentStoreOpenResult
{
    log_diagnostic("store.opening", {
                                        {"path", path, false}
    });
    auto connection = open_sqlite_connection(path);
    if (!connection.has_value())
    {
        log_diagnostic("store.rejected",
                       {
                           {"path",   path,                                     false},
                           {"reason", "unable to open SQLite persistent store", false}
        });
        return {false, "unable to open SQLite persistent store", {}};
    }
    auto& sqlite = **connection;
    if (!execute_sql(sqlite, "PRAGMA foreign_keys = ON"))
    {
        log_diagnostic("store.rejected",
                       {
                           {"path",   path,                                          false},
                           {"reason", "unable to configure SQLite persistent store", false}
        });
        return {false, "unable to configure SQLite persistent store", {}};
    }
    if (load_table_names(sqlite).empty() && !initialize_current_schema(sqlite))
    {
        log_diagnostic("store.rejected",
                       {
                           {"path",   path,                                 false},
                           {"reason", "unable to initialize SQLite schema", false}
        });
        return {false, "unable to initialize SQLite schema", {}};
    }

    auto store = PersistentStore{};
    store.open = true;
    store.backend = PersistentStoreBackend::sqlite;
    store.sqlite_path = path;
    store.schema = load_schema_state(sqlite);
    log_diagnostic("store.schema_loaded",
                   {
                       {"path",    path,                                 false},
                       {"version", std::to_string(store.schema.version), false}
    });
    if (store.schema.version < current_schema_version())
    {
        log_diagnostic("store.migrating", {
                                              {"path",            path,                                     false},
                                              {"current_version", std::to_string(store.schema.version),     false},
                                              {"target_version",  std::to_string(current_schema_version()), false}
        });
        auto migrated = apply_pending_migrations(sqlite, store.schema);
        if (!migrated.has_value())
        {
            log_diagnostic("store.rejected",
                           {
                               {"path",   path,                              false},
                               {"reason", "unable to migrate SQLite schema", false}
            });
            return {false, "unable to migrate SQLite schema", {}};
        }
        store.schema = std::move(*migrated);
        log_diagnostic("store.migrated",
                       {
                           {"path",    path,                                 false},
                           {"version", std::to_string(store.schema.version), false}
        });
    }
    if (!load_persistent_rows(sqlite, store))
    {
        log_diagnostic("store.rejected",
                       {
                           {"path",   path,                            false},
                           {"reason", "unable to hydrate SQLite rows", false}
        });
        return {false, "unable to hydrate SQLite rows", {}};
    }
    restore_sync_stream_id(store);

    auto compatibility = validate_persistent_store(store);
    if (!compatibility.valid)
    {
        log_diagnostic("store.rejected", {
                                             {"path",   path,                 false},
                                             {"reason", compatibility.reason, false}
        });
        return {false, compatibility.reason, {}};
    }
    log_diagnostic("store.ready", {
                                      {"path",    path,                                 false},
                                      {"version", std::to_string(store.schema.version), false}
    });
    return {true, {}, std::move(store)};
}

namespace detail
{

    auto persist_statement_to_backend(PersistentStore const& store, PreparedStatement const& statement) -> bool
    {
        return persist_transaction_to_backend(store, {statement});
    }

    auto persist_transaction_to_backend(PersistentStore const& store, std::vector<PreparedStatement> const& statements)
        -> bool
    {
        if (store.backend == PersistentStoreBackend::memory)
        {
            return true;
        }
        if (store.backend == PersistentStoreBackend::postgresql)
        {
            return persist_transaction_to_postgresql(store, statements);
        }
        if (store.sqlite_path.empty())
        {
            return false;
        }
        auto connection = open_sqlite_connection(store.sqlite_path);
        return connection.has_value() && execute_sql(**connection, "PRAGMA foreign_keys = ON") &&
               execute_transaction(**connection, statements);
    }

} // namespace detail

} // namespace merovingian::database
