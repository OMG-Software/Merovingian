// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/database/postgresql_store.hpp"
#include "merovingian/database/schema.hpp"
#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"

#include <libpq-fe.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace merovingian::database
{
namespace
{

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

    struct PostgresqlConnectionDeleter final
    {
        auto operator()(PGconn* connection) const noexcept -> void
        {
            PQfinish(connection);
        }
    };

    struct PostgresqlResultDeleter final
    {
        auto operator()(PGresult* result) const noexcept -> void
        {
            PQclear(result);
        }
    };

    using PostgresqlConnectionPtr = std::unique_ptr<PGconn, PostgresqlConnectionDeleter>;
    using PostgresqlResultPtr = std::unique_ptr<PGresult, PostgresqlResultDeleter>;

    [[nodiscard]] auto starts_with(std::string_view value, std::string_view prefix) noexcept -> bool
    {
        return value.size() >= prefix.size() && value.substr(0U, prefix.size()) == prefix;
    }

    [[nodiscard]] auto has_control_character(std::string_view value) noexcept -> bool
    {
        return std::ranges::any_of(value, [](char character) {
            auto const byte = static_cast<unsigned char>(character);
            return byte < 0x20U || byte == 0x7FU;
        });
    }

    [[nodiscard]] auto looks_like_key_value_conninfo(std::string_view conninfo) noexcept -> bool
    {
        auto const equals = conninfo.find('=');
        return equals != std::string_view::npos && equals > 0U;
    }

    [[nodiscard]] auto looks_like_postgresql_uri(std::string_view conninfo) noexcept -> bool
    {
        return starts_with(conninfo, "postgresql://") || starts_with(conninfo, "postgres://");
    }

    [[nodiscard]] auto redact_uri_password(std::string_view conninfo) -> std::string
    {
        auto redacted = std::string{conninfo};
        auto const scheme_end = redacted.find("://");
        if (scheme_end == std::string::npos)
        {
            return redacted;
        }

        auto const authority_begin = scheme_end + 3U;
        auto const authority_end = redacted.find_first_of("/?", authority_begin);
        auto const userinfo_end = redacted.find('@', authority_begin);
        if (userinfo_end == std::string::npos || (authority_end != std::string::npos && userinfo_end > authority_end))
        {
            return redacted;
        }

        auto const password_begin = redacted.find(':', authority_begin);
        if (password_begin == std::string::npos || password_begin > userinfo_end)
        {
            return redacted;
        }

        redacted.replace(password_begin + 1U, userinfo_end - password_begin - 1U, "redacted");
        return redacted;
    }

    [[nodiscard]] auto redact_key_value_password(std::string_view conninfo) -> std::string
    {
        auto redacted = std::string{conninfo};
        auto cursor = std::size_t{0U};
        while (cursor < redacted.size())
        {
            auto const password_key = redacted.find("password=", cursor);
            if (password_key == std::string::npos)
            {
                break;
            }

            auto const value_begin = password_key + std::string_view{"password="}.size();
            auto value_end = redacted.find(' ', value_begin);
            if (value_end == std::string::npos)
            {
                value_end = redacted.size();
            }
            redacted.replace(value_begin, value_end - value_begin, "redacted");
            cursor = value_begin + std::string_view{"redacted"}.size();
        }
        return redacted;
    }

    [[nodiscard]] auto connection_error(PGconn& connection) -> std::string
    {
        auto const* error = PQerrorMessage(&connection);
        if (error == nullptr || std::string_view{error}.empty())
        {
            return "PostgreSQL connection failed";
        }
        return std::string{error};
    }

    [[nodiscard]] auto result_error(PGresult& result) -> std::string
    {
        auto const* error = PQresultErrorMessage(&result);
        if (error == nullptr || std::string_view{error}.empty())
        {
            return "PostgreSQL statement failed";
        }
        return std::string{error};
    }

    [[nodiscard]] auto result_is_success(PGresult& result) noexcept -> bool
    {
        auto const status = PQresultStatus(&result);
        return status == PGRES_COMMAND_OK || status == PGRES_TUPLES_OK;
    }

    [[nodiscard]] auto command_is_success(PGresult& result) noexcept -> bool
    {
        return PQresultStatus(&result) == PGRES_COMMAND_OK;
    }

    [[nodiscard]] auto load_result_rows(PGresult& result) -> std::vector<std::vector<std::string>>
    {
        auto rows = std::vector<std::vector<std::string>>{};
        auto const row_count = PQntuples(&result);
        auto const column_count = PQnfields(&result);
        if (row_count <= 0 || column_count <= 0)
        {
            return rows;
        }

        rows.reserve(static_cast<std::size_t>(row_count));
        for (auto row = 0; row < row_count; ++row)
        {
            auto values = std::vector<std::string>{};
            values.reserve(static_cast<std::size_t>(column_count));
            for (auto column = 0; column < column_count; ++column)
            {
                if (PQgetisnull(&result, row, column) == 1)
                {
                    values.emplace_back();
                    continue;
                }
                auto const* value = PQgetvalue(&result, row, column);
                auto const length = PQgetlength(&result, row, column);
                values.emplace_back(value == nullptr ? std::string{}
                                                     : std::string{value, static_cast<std::size_t>(length)});
            }
            rows.push_back(std::move(values));
        }
        return rows;
    }

    [[nodiscard]] auto execute_raw_command(PGconn& connection, std::string_view sql) -> bool
    {
        auto command = std::string{sql};
        auto result = PostgresqlResultPtr{PQexec(&connection, command.c_str())};
        return result != nullptr && command_is_success(*result);
    }

    [[nodiscard]] auto execute_prepared_statement(PGconn& connection, PreparedStatement const& statement) -> QueryResult
    {
        auto const validation = prepared_statement_is_valid(statement);
        if (!validation.valid)
        {
            return {false, validation.reason, {}};
        }
        if (statement.parameters.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()))
        {
            return {false, "too many PostgreSQL statement parameters", {}};
        }

        auto parameter_values = std::vector<char const*>{};
        parameter_values.reserve(statement.parameters.size());
        for (auto const& parameter : statement.parameters)
        {
            parameter_values.push_back(parameter.value.c_str());
        }

        auto* const values = parameter_values.empty() ? nullptr : parameter_values.data();
        auto result = PostgresqlResultPtr{PQexecParams(&connection, statement.sql.c_str(),
                                                       static_cast<int>(statement.parameters.size()), nullptr, values,
                                                       nullptr, nullptr, 0)};
        if (result == nullptr)
        {
            return {false, connection_error(connection), {}};
        }
        if (!result_is_success(*result))
        {
            return {false, result_error(*result), {}};
        }
        return {true, {}, load_result_rows(*result)};
    }

    [[nodiscard]] auto execute_postgresql_transaction(PGconn& connection,
                                                      std::vector<PreparedStatement> const& statements) -> bool
    {
        if (!execute_raw_command(connection, "BEGIN"))
        {
            return false;
        }
        for (auto const& statement : statements)
        {
            auto result = execute_prepared_statement(connection, statement);
            if (!result.ok)
            {
                std::ignore = execute_raw_command(connection, "ROLLBACK");
                return false;
            }
        }
        if (!execute_raw_command(connection, "COMMIT"))
        {
            std::ignore = execute_raw_command(connection, "ROLLBACK");
            return false;
        }
        return true;
    }

    [[nodiscard]] auto create_table_if_missing_sql(SchemaTableDefinition const& table) -> std::string
    {
        return "CREATE TABLE IF NOT EXISTS " + std::string{table.name} + " (" + std::string{table.columns_sql} + ")";
    }

    [[nodiscard]] auto migration_record_statement(std::uint32_t version, std::string name) -> PreparedStatement
    {
        return {
            "postgresql_record_migration_" + std::to_string(version),
            "INSERT INTO schema_migrations VALUES ($1, $2, $3) ON CONFLICT (version) DO NOTHING",
            {{std::to_string(version), false}, {std::move(name), false}, {"upgrade", false}}
        };
    }

    [[nodiscard]] auto query_rows(PostgresqlConnection& connection, std::string name, std::string sql) -> QueryResult
    {
        return connection.execute({std::move(name), std::move(sql), {}});
    }

    // Returns whether the Merovingian schema specifically has been bootstrapped,
    // detected by the presence of the `schema_migrations` ledger. Looking only
    // at "any table in public" misclassifies shared databases that hold
    // unrelated tables and would skip bootstrap, then fail downstream when
    // `schema_migrations` turns out to be missing.
    [[nodiscard]] auto merovingian_schema_is_initialized(PostgresqlConnection& connection) -> std::optional<bool>
    {
        auto tables = query_rows(
            connection, "postgresql_detect_merovingian_schema",
            "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_name = "
            "'schema_migrations' LIMIT 1");
        if (!tables.ok)
        {
            return std::nullopt;
        }
        return !tables.rows.empty();
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

    auto load_persistent_rows(PostgresqlConnection& connection, PersistentStore& store) -> bool
    {
        auto users = query_rows(connection, "postgresql_load_users",
                                "SELECT user_id, password_hash, locked, suspended, admin FROM users ORDER BY user_id");
        if (!users.ok)
        {
            return false;
        }
        for (auto const& row : users.rows)
        {
            if (row.size() >= 5U)
            {
                store.users.push_back(
                    {row[0], row[1], text_is_true(row[2]), text_is_true(row[3]), text_is_true(row[4])});
            }
        }

        auto devices = query_rows(connection, "postgresql_load_devices",
                                  "SELECT user_id, device_id, display_name FROM devices ORDER BY user_id, device_id");
        if (!devices.ok)
        {
            return false;
        }
        for (auto const& row : devices.rows)
        {
            if (row.size() >= 3U)
            {
                store.devices.push_back({row[0], row[1], row[2]});
            }
        }

        auto tokens =
            query_rows(connection, "postgresql_load_access_tokens",
                       "SELECT user_id, device_id, token_hash, revoked, expires_at FROM access_tokens ORDER BY token_hash");
        if (!tokens.ok)
        {
            return false;
        }
        for (auto const& row : tokens.rows)
        {
            if (row.size() >= 4U)
            {
                store.access_tokens.push_back({row[0], row[1], row[2], text_is_true(row[3]),
                                               row.size() >= 5U ? parse_expires_at(row[4]) : std::nullopt});
            }
        }

        auto refresh_tokens =
            query_rows(connection, "postgresql_load_refresh_tokens",
                       "SELECT user_id, device_id, token_hash, revoked, expires_at FROM refresh_tokens ORDER BY token_hash");
        if (!refresh_tokens.ok)
        {
            return false;
        }
        for (auto const& row : refresh_tokens.rows)
        {
            if (row.size() >= 4U)
            {
                store.refresh_tokens.push_back({row[0], row[1], row[2], text_is_true(row[3]),
                                                row.size() >= 5U ? parse_expires_at(row[4]) : std::nullopt});
            }
        }

        auto server_signing_keys =
            query_rows(connection, "postgresql_load_server_signing_keys",
                       "SELECT server_name, key_id, public_key, valid_until_ts, secret_key FROM server_signing_keys "
                       "ORDER BY server_name, key_id");
        if (!server_signing_keys.ok)
        {
            return false;
        }
        for (auto const& row : server_signing_keys.rows)
        {
            if (row.size() >= 5U)
            {
                store.server_signing_keys.push_back({row[0], row[1], row[2], parse_u64(row[3]), row[4]});
            }
        }

        auto federation_destinations =
            query_rows(connection, "postgresql_load_federation_destinations",
                       "SELECT server_name, state, retry_after_ts, last_success_ts, consecutive_failures FROM "
                       "federation_destinations ORDER BY server_name");
        if (!federation_destinations.ok)
        {
            return false;
        }
        for (auto const& row : federation_destinations.rows)
        {
            if (row.size() >= 5U)
            {
                store.federation_destinations.push_back({row[0], row[1], parse_u64(row[2]), parse_u64(row[3]),
                                                         static_cast<std::uint32_t>(parse_u64(row[4]))});
            }
        }

        auto federation_transactions =
            query_rows(connection, "postgresql_load_federation_transactions",
                       "SELECT transaction_id, server_name, method, target, origin, origin_server_ts, body, "
                       "retry_count, next_retry_ts FROM federation_transactions ORDER BY transaction_id");
        if (!federation_transactions.ok)
        {
            return false;
        }
        for (auto const& row : federation_transactions.rows)
        {
            if (row.size() >= 9U)
            {
                store.federation_transactions.push_back({row[0], row[1], row[2], row[3], row[4], row[5], row[6],
                                                         static_cast<std::uint32_t>(parse_u64(row[7])),
                                                         parse_u64(row[8])});
            }
        }

        auto rooms = query_rows(connection, "postgresql_load_rooms",
                                "SELECT room_id, creator_user_id FROM rooms ORDER BY room_id");
        if (!rooms.ok)
        {
            return false;
        }
        for (auto const& row : rooms.rows)
        {
            if (row.size() >= 2U)
            {
                store.rooms.push_back({row[0], row[1]});
            }
        }

        auto memberships = query_rows(
            connection, "postgresql_load_membership",
            "SELECT room_id, user_id, membership, stream_ordering FROM membership ORDER BY room_id, user_id");
        if (!memberships.ok)
        {
            return false;
        }
        for (auto const& row : memberships.rows)
        {
            if (row.size() >= 4U)
            {
                store.memberships.push_back({row[0], row[1], row[2], parse_u64(row[3])});
            }
        }

        auto invites =
            query_rows(connection, "postgresql_load_invites",
                       "SELECT room_id, user_id, sender_user_id, event_id, signed_event_json, invite_state_json, "
                       "stream_ordering FROM invites ORDER BY room_id, user_id");
        if (!invites.ok)
        {
            return false;
        }
        for (auto const& row : invites.rows)
        {
            if (row.size() >= 7U)
            {
                store.invites.push_back({row[0], row[1], row[2], row[3], row[4], parse_invite_state_events_json(row[5]),
                                         parse_u64(row[6])});
            }
        }

        auto events = query_rows(
            connection, "postgresql_load_events",
            "SELECT event_id, room_id, sender_user_id, json, depth, stream_ordering FROM events ORDER BY event_id");
        if (!events.ok)
        {
            return false;
        }
        for (auto const& row : events.rows)
        {
            if (row.size() >= 6U)
            {
                store.events.push_back({row[0], row[1], row[2], row[3], parse_u64(row[4]), parse_u64(row[5])});
            }
        }

        auto event_edges = query_rows(connection, "postgresql_load_event_edges",
                                      "SELECT event_id, prev_event_id FROM event_edges ORDER BY event_id");
        if (!event_edges.ok)
        {
            return false;
        }
        for (auto const& row : event_edges.rows)
        {
            if (row.size() >= 2U)
            {
                store.event_edges.push_back({row[0], row[1]});
            }
        }

        auto event_auth = query_rows(connection, "postgresql_load_event_auth",
                                     "SELECT event_id, auth_event_id FROM event_auth ORDER BY event_id");
        if (!event_auth.ok)
        {
            return false;
        }
        for (auto const& row : event_auth.rows)
        {
            if (row.size() >= 2U)
            {
                store.event_auth.push_back({row[0], row[1]});
            }
        }

        auto event_signatures = query_rows(
            connection, "postgresql_load_event_signatures",
            "SELECT event_id, server_name, key_id, signature FROM event_signatures ORDER BY event_id, server_name");
        if (!event_signatures.ok)
        {
            return false;
        }
        for (auto const& row : event_signatures.rows)
        {
            if (row.size() >= 4U)
            {
                store.event_signatures.push_back({row[0], row[1], row[2], row[3]});
            }
        }

        auto state = query_rows(connection, "postgresql_load_current_state",
                                "SELECT room_id, event_type, state_key, event_id FROM current_state ORDER BY room_id, "
                                "event_type, state_key");
        if (!state.ok)
        {
            return false;
        }
        for (auto const& row : state.rows)
        {
            if (row.size() >= 4U)
            {
                store.state.push_back({row[0], row[1], row[2], row[3]});
            }
        }

        auto device_keys = query_rows(connection, "postgresql_load_device_keys",
                                      "SELECT user_id, device_id, json FROM device_keys ORDER BY user_id, device_id");
        if (!device_keys.ok)
        {
            return false;
        }
        for (auto const& row : device_keys.rows)
        {
            if (row.size() >= 3U)
            {
                store.device_keys.push_back({row[0], row[1], row[2]});
            }
        }

        auto one_time_keys = query_rows(
            connection, "postgresql_load_one_time_keys",
            "SELECT user_id, device_id, key_id, json FROM one_time_keys ORDER BY user_id, device_id, key_id");
        if (!one_time_keys.ok)
        {
            return false;
        }
        for (auto const& row : one_time_keys.rows)
        {
            if (row.size() >= 4U)
            {
                store.one_time_keys.push_back({row[0], row[1], row[2], row[3]});
            }
        }

        auto fallback_keys = query_rows(
            connection, "postgresql_load_fallback_keys",
            "SELECT user_id, device_id, key_id, json FROM fallback_keys ORDER BY user_id, device_id, key_id");
        if (!fallback_keys.ok)
        {
            return false;
        }
        for (auto const& row : fallback_keys.rows)
        {
            if (row.size() >= 4U)
            {
                store.fallback_keys.push_back({row[0], row[1], row[2], row[3]});
            }
        }

        auto cross_signing_keys =
            query_rows(connection, "postgresql_load_cross_signing_keys",
                       "SELECT user_id, key_type, json FROM cross_signing_keys ORDER BY user_id, key_type");
        if (!cross_signing_keys.ok)
        {
            return false;
        }
        for (auto const& row : cross_signing_keys.rows)
        {
            if (row.size() >= 3U)
            {
                store.cross_signing_keys.push_back({row[0], row[1], row[2]});
            }
        }

        auto key_signatures =
            query_rows(connection, "postgresql_load_key_signatures",
                       "SELECT signer_user_id, target_user_id, target_device_id, json FROM key_signatures ORDER BY "
                       "signer_user_id, target_user_id, target_device_id");
        if (!key_signatures.ok)
        {
            return false;
        }
        for (auto const& row : key_signatures.rows)
        {
            if (row.size() >= 4U)
            {
                store.key_signatures.push_back({row[0], row[1], row[2], row[3]});
            }
        }

        auto key_backup_versions =
            query_rows(connection, "postgresql_load_key_backup_versions",
                       "SELECT user_id, version, json FROM key_backup_versions ORDER BY user_id, version");
        if (!key_backup_versions.ok)
        {
            return false;
        }
        for (auto const& row : key_backup_versions.rows)
        {
            if (row.size() >= 3U)
            {
                store.key_backup_versions.push_back({row[0], row[1], row[2]});
            }
        }

        auto key_backup_sessions = query_rows(
            connection, "postgresql_load_key_backup_sessions",
            "SELECT user_id, version, room_id, session_id, json FROM key_backup_sessions ORDER BY user_id, version, "
            "room_id, session_id");
        if (!key_backup_sessions.ok)
        {
            return false;
        }
        for (auto const& row : key_backup_sessions.rows)
        {
            if (row.size() >= 5U)
            {
                store.key_backup_sessions.push_back({row[0], row[1], row[2], row[3], row[4]});
            }
        }

        auto media = query_rows(connection, "postgresql_load_media",
                                "SELECT media_id, owner_user_id, content_type, size_bytes, hash_algorithm, digest, "
                                "quarantined, removed FROM media ORDER BY media_id");
        if (!media.ok)
        {
            return false;
        }
        for (auto const& row : media.rows)
        {
            if (row.size() >= 8U)
            {
                store.local_media.push_back({row[0], row[1], row[2], parse_u64(row[3]), row[4], row[5],
                                             text_is_true(row[6]), text_is_true(row[7])});
            }
        }

        auto media_blobs =
            query_rows(connection, "postgresql_load_media_blobs",
                       "SELECT storage_id, hash_algorithm, digest, size_bytes, bytes, ref_count FROM media_blobs "
                       "ORDER BY storage_id");
        if (!media_blobs.ok)
        {
            return false;
        }
        for (auto const& row : media_blobs.rows)
        {
            if (row.size() >= 6U)
            {
                store.media_blobs.push_back({row[0], row[1], row[2], parse_u64(row[3]), row[4], parse_u64(row[5])});
            }
        }

        auto remote_media = query_rows(connection, "postgresql_load_remote_media",
                                       "SELECT server_name, media_id, content_type, size_bytes, quarantined FROM "
                                       "remote_media ORDER BY server_name, media_id");
        if (!remote_media.ok)
        {
            return false;
        }
        for (auto const& row : remote_media.rows)
        {
            if (row.size() >= 5U)
            {
                store.remote_media.push_back({row[0], row[1], row[2], parse_u64(row[3]), text_is_true(row[4])});
            }
        }

        auto audit_log =
            query_rows(connection, "postgresql_load_audit_log",
                       "SELECT category, event_type, actor, target, reason FROM audit_log ORDER BY event_type, actor");
        if (!audit_log.ok)
        {
            return false;
        }
        for (auto const& row : audit_log.rows)
        {
            if (row.size() >= 5U)
            {
                store.audit_log.push_back({row[0], row[1], row[2], row[3], row[4]});
            }
        }

        auto admin_actions =
            query_rows(connection, "postgresql_load_admin_actions",
                       "SELECT admin_user_id, action, target FROM admin_actions ORDER BY admin_user_id, action");
        if (!admin_actions.ok)
        {
            return false;
        }
        for (auto const& row : admin_actions.rows)
        {
            if (row.size() >= 3U)
            {
                store.admin_actions.push_back({row[0], row[1], row[2]});
            }
        }

        auto policy_rules = query_rows(connection, "postgresql_load_policy_rules",
                                       "SELECT rule_id, scope, entity, action, reason FROM policy_rules ORDER BY "
                                       "rule_id");
        if (!policy_rules.ok)
        {
            return false;
        }
        for (auto const& row : policy_rules.rows)
        {
            if (row.size() >= 5U)
            {
                store.policy_rules.push_back({row[0], row[1], row[2], row[3], row[4]});
            }
        }

        auto account_data = query_rows(connection, "postgresql_load_account_data",
                                       "SELECT user_id, event_type, json, stream_id FROM account_data ORDER "
                                       "BY stream_id");
        if (!account_data.ok)
        {
            return false;
        }
        for (auto const& row : account_data.rows)
        {
            if (row.size() >= 4U)
            {
                auto entry = PersistentAccountData{};
                entry.user_id = row[0];
                entry.event_type = row[1];
                entry.content_json = row[2];
                entry.stream_id = parse_u64(row[3]);
                store.account_data.push_back(std::move(entry));
            }
        }

        auto room_account_data = query_rows(connection, "postgresql_load_room_account_data",
                                            "SELECT user_id, room_id, event_type, stream_id, json FROM "
                                            "room_account_data ORDER BY stream_id");
        if (!room_account_data.ok)
        {
            return false;
        }
        for (auto const& row : room_account_data.rows)
        {
            if (row.size() >= 5U)
            {
                auto entry = PersistentAccountData{};
                entry.user_id = row[0];
                entry.room_id = row[1];
                entry.event_type = row[2];
                entry.stream_id = parse_u64(row[3]);
                entry.content_json = row[4];
                store.account_data.push_back(std::move(entry));
            }
        }

        auto to_device = query_rows(connection, "postgresql_load_to_device_messages",
                                    "SELECT stream_id, sender_user_id, target_user_id, target_device_id, "
                                    "message_type, content FROM to_device_messages ORDER BY stream_id");
        if (!to_device.ok)
        {
            return false;
        }
        for (auto const& row : to_device.rows)
        {
            if (row.size() >= 6U)
            {
                auto entry = PersistentToDeviceMessage{};
                entry.stream_id = parse_u64(row[0]);
                entry.sender_user_id = row[1];
                entry.target_user_id = row[2];
                entry.target_device_id = row[3];
                entry.message_type = row[4];
                entry.content_json = row[5];
                store.to_device_messages.push_back(std::move(entry));
            }
        }

        auto device_list_changes = query_rows(connection, "postgresql_load_device_list_changes",
                                              "SELECT stream_id, observer_user_id, subject_user_id, change_type FROM "
                                              "device_list_changes ORDER BY stream_id");
        if (!device_list_changes.ok)
        {
            return false;
        }
        for (auto const& row : device_list_changes.rows)
        {
            if (row.size() >= 4U)
            {
                auto entry = PersistentDeviceListChange{};
                entry.stream_id = parse_u64(row[0]);
                entry.observer_user_id = row[1];
                entry.subject_user_id = row[2];
                entry.change_type = row[3];
                store.device_list_changes.push_back(std::move(entry));
            }
        }

        auto presence = query_rows(connection, "postgresql_load_presence_state",
                                   "SELECT user_id, stream_id, presence, status_msg, last_active_ago, "
                                   "currently_active FROM presence_state ORDER BY stream_id");
        if (!presence.ok)
        {
            return false;
        }
        for (auto const& row : presence.rows)
        {
            if (row.size() >= 6U)
            {
                auto entry = PersistentPresence{};
                entry.user_id = row[0];
                entry.stream_id = parse_u64(row[1]);
                entry.presence = row[2];
                entry.status_msg = row[3];
                entry.last_active_ago = static_cast<std::int64_t>(parse_u64(row[4]));
                entry.currently_active = text_is_true(row[5]);
                store.presence_states.push_back(std::move(entry));
            }
        }

        auto filters = query_rows(connection, "postgresql_load_filters",
                                  "SELECT user_id, filter_id, json FROM filters ORDER BY user_id, filter_id");
        if (!filters.ok)
        {
            return false;
        }
        for (auto const& row : filters.rows)
        {
            if (row.size() >= 3U)
            {
                store.filters.push_back({row[0], row[1], row[2]});
            }
        }

        auto room_aliases = query_rows(connection, "postgresql_load_room_aliases",
                                       "SELECT room_alias, room_id FROM room_aliases ORDER BY room_alias");
        if (!room_aliases.ok)
        {
            return false;
        }
        for (auto const& row : room_aliases.rows)
        {
            if (row.size() >= 2U)
            {
                store.room_aliases.push_back({row[0], row[1]});
            }
        }

        auto client_txns = query_rows(connection, "postgresql_load_client_txn_ids",
                                      "SELECT user_id, room_id, event_type, txn_id, event_id FROM client_txn_ids");
        if (!client_txns.ok)
        {
            return false;
        }
        for (auto const& row : client_txns.rows)
        {
            if (row.size() >= 5U)
            {
                store.client_txn_ids.push_back({row[0], row[1], row[2], row[3], row[4]});
            }
        }

        auto const watermark = query_rows(connection, "postgresql_load_sync_stream_watermark",
                                          "SELECT watermark FROM sync_stream_watermark");
        if (!watermark.ok)
        {
            return false;
        }
        for (auto const& row : watermark.rows)
        {
            if (!row.empty())
            {
                store.next_sync_stream_id = parse_u64(row[0]);
            }
        }
        return true;
    }

    [[nodiscard]] auto load_schema_state(PostgresqlConnection& connection) -> std::optional<SchemaState>
    {
        auto state = SchemaState{};
        auto tables = query_rows(
            connection, "postgresql_load_table_names",
            "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY table_name");
        if (!tables.ok)
        {
            return std::nullopt;
        }
        for (auto const& row : tables.rows)
        {
            if (!row.empty())
            {
                state.tables.push_back(row.front());
            }
        }

        auto migrations = query_rows(connection, "postgresql_load_schema_migrations",
                                     "SELECT version, name, direction FROM schema_migrations ORDER BY version");
        if (!migrations.ok)
        {
            return std::nullopt;
        }
        for (auto const& row : migrations.rows)
        {
            if (row.size() >= 3U)
            {
                auto const version = static_cast<std::uint32_t>(parse_u64(row[0]));
                state.applied_migrations.push_back(
                    {version, row[1],
                     row[2] == "downgrade" ? MigrationDirection::downgrade : MigrationDirection::upgrade});
                if (version > state.version)
                {
                    state.version = version;
                }
            }
        }
        return state;
    }

    [[nodiscard]] auto apply_pending_migrations(PostgresqlConnection& connection, SchemaState state)
        -> std::optional<SchemaState>
    {
        auto const plan = migration_plan_for(state);
        auto const validation = migration_plan_is_valid(plan);
        if (!validation.valid)
        {
            return std::nullopt;
        }
        for (auto const& step : plan.steps)
        {
            auto statements = step.statements;
            statements.push_back(migration_record_statement(step.version, step.name));
            if (!connection.execute_transaction(statements))
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

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields) -> void
    {
        LOG_DEBUG(observability::diagnostic_log_summary("postgresql_store", event, std::move(fields)));
    }

} // namespace

struct PostgresqlConnectionHandle final
{
    PostgresqlConnectionPtr connection{};
};

PostgresqlConnection::PostgresqlConnection() noexcept = default;
PostgresqlConnection::PostgresqlConnection(std::unique_ptr<PostgresqlConnectionHandle> handle) noexcept
    : handle_{std::move(handle)}
{
}
PostgresqlConnection::PostgresqlConnection(PostgresqlConnection&& other) noexcept = default;
auto PostgresqlConnection::operator=(PostgresqlConnection&& other) noexcept -> PostgresqlConnection& = default;
PostgresqlConnection::~PostgresqlConnection() = default;

auto PostgresqlConnection::open() const noexcept -> bool
{
    return handle_ != nullptr && handle_->connection != nullptr && PQstatus(handle_->connection.get()) == CONNECTION_OK;
}

auto PostgresqlConnection::execute(PreparedStatement const& statement) -> QueryResult
{
    if (!open())
    {
        return {false, "PostgreSQL connection is not open", {}};
    }

    return execute_prepared_statement(*handle_->connection, statement);
}

auto PostgresqlConnection::execute_transaction(std::vector<PreparedStatement> const& statements) -> bool
{
    return open() && execute_postgresql_transaction(*handle_->connection, statements);
}

auto validate_postgresql_conninfo(std::string_view conninfo) -> PostgresqlConnectionPolicyResult
{
    if (conninfo.empty())
    {
        return {false, "PostgreSQL connection info must not be empty"};
    }
    if (has_control_character(conninfo))
    {
        return {false, "PostgreSQL connection info must not contain control characters"};
    }
    if (!looks_like_postgresql_uri(conninfo) && !looks_like_key_value_conninfo(conninfo))
    {
        return {false, "PostgreSQL connection info must use a PostgreSQL URI or key/value form"};
    }
    return {true, {}};
}

auto redact_postgresql_conninfo(std::string_view conninfo) -> std::string
{
    auto redacted = looks_like_postgresql_uri(conninfo) ? redact_uri_password(conninfo) : std::string{conninfo};
    return redact_key_value_password(redacted);
}

auto postgresql_schema_bootstrap_statements() -> std::vector<PreparedStatement>
{
    auto statements = std::vector<PreparedStatement>{};
    for (auto const& table : initial_schema_definitions())
    {
        statements.push_back({"postgresql_create_" + std::string{table.name}, create_table_if_missing_sql(table), {}});
    }
    // Bootstrap records only the initial schema row. Runtime startup can
    // then apply newer numbered migrations against the freshly created
    // tables when current_schema_version() is greater than 1.
    statements.push_back(migration_record_statement(1U, "initial_schema"));
    return statements;
}

auto open_postgresql_connection(std::string_view conninfo) -> PostgresqlConnectionOpenResult
{
    auto const policy = validate_postgresql_conninfo(conninfo);
    auto const redacted = redact_postgresql_conninfo(conninfo);
    log_diagnostic("connection.opening", {
                                             {"conninfo", redacted, false}
    });
    if (!policy.allowed)
    {
        log_diagnostic("connection.rejected", {
                                                  {"conninfo", redacted,      false},
                                                  {"reason",   policy.reason, false}
        });
        return {false, policy.reason, redacted, {}};
    }

    auto conninfo_string = std::string{conninfo};
    auto connection = PostgresqlConnectionPtr{PQconnectdb(conninfo_string.c_str())};
    if (connection == nullptr)
    {
        log_diagnostic("connection.rejected",
                       {
                           {"conninfo", redacted,                       false},
                           {"reason",   "connection allocation failed", false}
        });
        return {false, "PostgreSQL connection allocation failed", redacted, {}};
    }
    if (PQstatus(connection.get()) != CONNECTION_OK)
    {
        auto reason = connection_error(*connection);
        log_diagnostic("connection.rejected", {
                                                  {"conninfo", redacted, false},
                                                  {"reason",   reason,   false}
        });
        return {false, reason, redacted, {}};
    }

    log_diagnostic("connection.ready", {
                                           {"conninfo", redacted, false}
    });
    auto handle = std::make_unique<PostgresqlConnectionHandle>();
    handle->connection = std::move(connection);
    return {true, {}, redacted, PostgresqlConnection{std::move(handle)}};
}

auto open_postgresql_persistent_store(std::string_view conninfo) -> PersistentStoreOpenResult
{
    log_diagnostic("store.opening", {
                                        {"backend", "postgresql", false}
    });
    auto opened = open_postgresql_connection(conninfo);
    if (!opened.ok)
    {
        log_diagnostic("store.rejected", {
                                             {"reason", opened.reason, false}
        });
        return {false, opened.reason, {}};
    }

    auto& connection = opened.connection;
    auto const has_schema = merovingian_schema_is_initialized(connection);
    if (!has_schema.has_value())
    {
        log_diagnostic("store.rejected", {
                                             {"reason", "unable to inspect schema", false}
        });
        return {false, "unable to inspect PostgreSQL schema", {}};
    }
    if (!*has_schema)
    {
        log_diagnostic("store.schema_bootstrapping", {});
        auto const bootstrap = postgresql_schema_bootstrap_statements();
        if (!connection.execute_transaction(bootstrap))
        {
            log_diagnostic("store.rejected", {
                                                 {"reason", "schema bootstrap failed", false}
            });
            return {false, "unable to initialize PostgreSQL schema", {}};
        }
        log_diagnostic("store.schema_bootstrapped", {});
    }

    auto schema = load_schema_state(connection);
    if (!schema.has_value())
    {
        log_diagnostic("store.rejected", {
                                             {"reason", "unable to hydrate schema state", false}
        });
        return {false, "unable to hydrate PostgreSQL schema state", {}};
    }
    log_diagnostic("store.schema_loaded", {
                                              {"version", std::to_string(schema->version), false}
    });

    auto store = PersistentStore{};
    store.open = true;
    store.backend = PersistentStoreBackend::postgresql;
    store.postgresql_conninfo = std::string{conninfo};
    store.schema = std::move(*schema);
    if (store.schema.version < current_schema_version())
    {
        log_diagnostic("store.migrating", {
                                              {"from", std::to_string(store.schema.version),     false},
                                              {"to",   std::to_string(current_schema_version()), false}
        });
        auto migrated = apply_pending_migrations(connection, store.schema);
        if (!migrated.has_value())
        {
            log_diagnostic("store.rejected", {
                                                 {"reason", "migration failed", false}
            });
            return {false, "unable to migrate PostgreSQL schema", {}};
        }
        log_diagnostic("store.migrated", {
                                             {"version", std::to_string(migrated->version), false}
        });
        store.schema = std::move(*migrated);
    }
    if (!load_persistent_rows(connection, store))
    {
        log_diagnostic("store.rejected", {
                                             {"reason", "unable to hydrate rows", false}
        });
        return {false, "unable to hydrate PostgreSQL persistent rows", {}};
    }
    restore_sync_stream_id(store);

    auto compatibility = validate_persistent_store(store);
    if (!compatibility.valid)
    {
        log_diagnostic("store.rejected", {
                                             {"reason", compatibility.reason, false}
        });
        return {false, compatibility.reason, {}};
    }
    log_diagnostic("store.ready",
                   {
                       {"backend", "postgresql",                         false},
                       {"version", std::to_string(store.schema.version), false}
    });
    return {true, {}, std::move(store)};
}

namespace
{

    [[nodiscard]] auto identifier_is_safe(std::string_view name) noexcept -> bool
    {
        if (name.empty() || name.size() > 63U)
        {
            return false;
        }
        if (!((name.front() >= 'a' && name.front() <= 'z') || (name.front() >= 'A' && name.front() <= 'Z') ||
              name.front() == '_'))
        {
            return false;
        }
        for (auto const character : name)
        {
            auto const allowed = (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
                                 (character >= '0' && character <= '9') || character == '_';
            if (!allowed)
            {
                return false;
            }
        }
        return true;
    }

} // namespace

auto set_postgresql_role(PostgresqlConnection& connection, std::string_view role_name) -> bool
{
    if (!connection.open() || !identifier_is_safe(role_name))
    {
        return false;
    }
    // Identifier safety is enforced above, so quoting with double quotes is
    // sufficient. We deliberately do NOT pass role through a $1 parameter:
    // SET ROLE does not accept a parameter form in PostgreSQL, only an
    // inline identifier or NONE.
    auto const sql = "SET ROLE \"" + std::string{role_name} + "\"";
    auto const result = connection.execute({"set_postgresql_role", sql, {}});
    return result.ok;
}

auto reset_postgresql_role(PostgresqlConnection& connection) -> bool
{
    if (!connection.open())
    {
        return false;
    }
    // SET ROLE NONE restores the authenticated session_user. `RESET ROLE`
    // would instead reapply the connection-time role configuration,
    // including any `ALTER ROLE ... SET ROLE` defaults, which keeps an
    // elevated role active when callers expect to drop back to the
    // login identity.
    auto const result = connection.execute({"reset_postgresql_role", "SET ROLE NONE", {}});
    return result.ok;
}

auto current_postgresql_user(PostgresqlConnection& connection) -> std::string
{
    if (!connection.open())
    {
        return {};
    }
    auto const result = connection.execute({"postgresql_current_user", "SELECT CURRENT_USER::text", {}});
    if (!result.ok || result.rows.empty() || result.rows.front().empty())
    {
        return {};
    }
    return result.rows.front().front();
}

namespace detail
{

    auto persist_transaction_to_postgresql(PersistentStore const& store,
                                           std::vector<PreparedStatement> const& statements) -> bool
    {
        if (store.postgresql_conninfo.empty())
        {
            return false;
        }
        auto opened = open_postgresql_connection(store.postgresql_conninfo);
        return opened.ok && opened.connection.execute_transaction(statements);
    }

} // namespace detail

} // namespace merovingian::database
