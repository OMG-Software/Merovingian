// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/database/PostgresqlConnection.hpp"

#include "merovingian/database/PostgresqlConnectionHandle.hpp"
#include "merovingian/database/PostgresqlExecution.hpp"
#include "merovingian/database/PostgresqlResultDeleter.hpp"
#include "merovingian/database/PreparedStatement.hpp"
#include "merovingian/database/QueryResult.hpp"

#include <libpq-fe.h>
#include <poll.h>

#include <cstddef>
#include <limits>
#include <memory>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

namespace merovingian::database
{

namespace
{

    using detail::bytea_type_oid;
    using detail::connection_error;
    using detail::execute_raw_command;
    using detail::load_result_rows;
    using detail::result_error;
    using detail::result_is_success;

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

        // Parameters marked `binary` (every `BLOB` column: media_blobs.bytes,
        // server_signing_keys.secret_key) travel in libpq's binary format, with
        // an explicit length and a declared bytea type. The raw bytes are then
        // never treated as a null-terminated C string (which truncates at the
        // first NUL), never parsed as text (which rejects invalid UTF-8) and
        // never subject to bytea's backslash escaping, so any byte sequence
        // arrives exactly. Declaring the type also keeps a parameter that
        // appears in more than one expression (`$5 = ''`, `ELSE $5`) bytea
        // rather than leaving it to inference. Text parameters keep the text
        // format and the server's own inference (type 0).
        auto const parameter_count = statement.parameters.size();
        auto parameter_types = std::vector<Oid>(parameter_count, Oid{0U});
        auto parameter_values = std::vector<char const*>{};
        parameter_values.reserve(parameter_count);
        auto parameter_lengths = std::vector<int>(parameter_count, 0);
        auto parameter_formats = std::vector<int>(parameter_count, 0);
        for (auto index = std::size_t{0U}; index < parameter_count; ++index)
        {
            auto const& parameter = statement.parameters[index];
            parameter_values.push_back(parameter.value.c_str());
            if (!parameter.binary)
            {
                continue;
            }
            if (parameter.value.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()))
            {
                return {false, "PostgreSQL binary parameter is too large", {}};
            }
            parameter_types[index] = bytea_type_oid;
            parameter_lengths[index] = static_cast<int>(parameter.value.size());
            parameter_formats[index] = 1;
        }

        auto* const values = parameter_values.empty() ? nullptr : parameter_values.data();
        auto* const types = parameter_types.empty() ? nullptr : parameter_types.data();
        auto* const lengths = parameter_lengths.empty() ? nullptr : parameter_lengths.data();
        auto* const formats = parameter_formats.empty() ? nullptr : parameter_formats.data();
        auto result = PostgresqlResultPtr{PQexecParams(
            &connection, statement.sql.c_str(), static_cast<int>(parameter_count), types, values, lengths, formats, 0)};
        if (result == nullptr)
        {
            return {false, connection_error(connection), {}};
        }
        if (!result_is_success(*result))
        {
            return {false, result_error(*result), {}};
        }
        auto rows = load_result_rows(*result);
        if (!rows.has_value())
        {
            return {false, "PostgreSQL returned a malformed bytea value", {}};
        }
        return {true, {}, std::move(*rows)};
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

} // namespace

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

auto PostgresqlConnection::reusable() noexcept -> bool
{
    if (!open() || PQtransactionStatus(handle_->connection.get()) != PQTRANS_IDLE)
    {
        return false;
    }
    // An idle connection has nothing to read: this server never LISTENs, so
    // readable means the server has sent something unasked, which in practice
    // is a termination notice followed by end-of-file (restart, idle reaper,
    // pg_terminate_backend). Such a connection is replaced, not reused.
    auto readiness = ::pollfd{PQsocket(handle_->connection.get()), POLLIN, 0};
    return readiness.fd >= 0 && ::poll(&readiness, 1U, 0) == 0;
}

} // namespace merovingian::database
