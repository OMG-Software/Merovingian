// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>

struct pg_conn;
struct pg_result;

// Module-internal (ADR-0513): the libpq result and command helpers that
// PostgresqlStore.cpp and PostgresqlConnection.cpp share. Not public API.
namespace merovingian::database::detail
{

// PostgreSQL's built-in type OID for bytea (pg_type.dat). Every `BLOB` column
// in the schema is translated to BYTEA, so this one OID is how a result
// column is recognised as binary, whichever table it came from.
inline constexpr unsigned int bytea_type_oid = 17U;

// The error text for a failed connection or a call that returned no result.
// Never the host, database, user or options: any of them may hold a secret.
[[nodiscard]] auto connection_error(pg_conn& connection) -> std::string;
// The server's message for a failed statement, or a generic one when it gave none.
[[nodiscard]] auto result_error(pg_result& result) -> std::string;
// Whether a statement succeeded, with or without rows.
[[nodiscard]] auto result_is_success(pg_result& result) noexcept -> bool;
// Whether a command that returns no rows succeeded.
[[nodiscard]] auto command_is_success(pg_result& result) noexcept -> bool;
// A text-format result's rows, with bytea columns decoded from their hex form.
// Nullopt when a bytea value cannot be decoded, so the caller fails the whole query.
[[nodiscard]] auto load_result_rows(pg_result& result) -> std::optional<std::vector<std::vector<std::string>>>;
// Runs one parameterless command such as BEGIN or COMMIT; true when it succeeded.
[[nodiscard]] auto execute_raw_command(pg_conn& connection, std::string_view sql) -> bool;

} // namespace merovingian::database::detail
