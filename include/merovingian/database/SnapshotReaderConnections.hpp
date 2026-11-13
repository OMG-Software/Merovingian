// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/PostgresqlConnection.hpp"
#include "merovingian/database/RoomReloadSnapshot.hpp"
#include "merovingian/database/SqliteConnectionDeleter.hpp"

#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

// Module-internal (ADR-0739): the reads main makes for a federation worker, split into opening a reader and reading
// through one, so `SnapshotReaderPool` can read through connections it opened before main entered a sandbox that
// forbids opening files and sockets. The path- and conninfo-taking forms in `PersistentStore.hpp` open, then read.
namespace merovingian::database::detail
{

// A read-only connection to main's SQLite file with its first read done; nullopt (logged) if it cannot be opened.
[[nodiscard]] auto open_sqlite_snapshot_reader(std::string const& path) -> std::optional<SqliteConnection>;
[[nodiscard]] auto load_room_ids_from_sqlite_connection(SqliteConnection& connection)
    -> std::optional<std::vector<std::string>>;
// One room's rows in one read transaction, which has ended when this returns.
[[nodiscard]] auto load_room_snapshot_from_sqlite_connection(SqliteConnection& connection, std::string_view room_id,
                                                             std::function<void(std::string_view)> const& after_table)
    -> std::optional<RoomReloadSnapshot>;

// A connection to main's PostgreSQL database, switched to the runtime role when one is configured.
[[nodiscard]] auto open_postgresql_snapshot_reader(std::string_view conninfo, std::string_view runtime_role)
    -> std::optional<PostgresqlConnection>;
[[nodiscard]] auto load_room_ids_from_postgresql_connection(PostgresqlConnection& connection)
    -> std::optional<std::vector<std::string>>;
// One room's rows in one REPEATABLE READ READ ONLY transaction, rolled back before this returns.
[[nodiscard]] auto load_room_snapshot_from_postgresql_connection(
    PostgresqlConnection& connection, std::string_view room_id,
    std::function<void(std::string_view)> const& after_table) -> std::optional<RoomReloadSnapshot>;

} // namespace merovingian::database::detail
