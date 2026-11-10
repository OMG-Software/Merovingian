// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/database/PostgresqlExecution.hpp"

#include "merovingian/database/PostgresqlResultDeleter.hpp"
#include "merovingian/database/PostgresqlStore.hpp"

#include <libpq-fe.h>

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace merovingian::database::detail
{

[[nodiscard]] auto connection_error(PGconn& /*connection*/) -> std::string
{
    // The host, dbname, user and even malformed options may contain secrets.
    return "PostgreSQL connection failed (connection details redacted)";
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

// Returns nullopt when a bytea value cannot be decoded: the caller fails the
// whole query rather than hand back an empty or garbled secret.
[[nodiscard]] auto load_result_rows(PGresult& result) -> std::optional<std::vector<std::vector<std::string>>>
{
    auto rows = std::vector<std::vector<std::string>>{};
    auto const row_count = PQntuples(&result);
    auto const column_count = PQnfields(&result);
    if (row_count <= 0 || column_count <= 0)
    {
        return rows;
    }

    // Result values come back in text format, where a bytea column is its
    // `\x` hex form (`SET bytea_output = 'hex'` is pinned at connection
    // open). Decode those columns here, once, so no caller ever sees hex
    // and no per-table special case is needed.
    auto column_is_bytea = std::vector<bool>{};
    column_is_bytea.reserve(static_cast<std::size_t>(column_count));
    for (auto column = 0; column < column_count; ++column)
    {
        column_is_bytea.push_back(PQftype(&result, column) == bytea_type_oid);
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
            auto text = value == nullptr ? std::string{} : std::string{value, static_cast<std::size_t>(length)};
            if (column_is_bytea[static_cast<std::size_t>(column)])
            {
                auto decoded = decode_postgresql_bytea_hex(text);
                if (!decoded.has_value())
                {
                    return std::nullopt;
                }
                text = std::move(*decoded);
            }
            values.push_back(std::move(text));
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

} // namespace merovingian::database::detail
