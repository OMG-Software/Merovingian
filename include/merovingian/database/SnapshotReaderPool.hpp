// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/ConnectionPool.hpp"
#include "merovingian/database/PersistentStoreBackend.hpp"
#include "merovingian/database/PostgresqlConnection.hpp"
#include "merovingian/database/RoomReloadSnapshot.hpp"
#include "merovingian/database/SqliteConnectionDeleter.hpp"

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::database
{

struct PersistentStore;

// ADR-0739: the database connections main reads a federation worker's store through (ADR-0733). They are opened when
// the pool is built, which is before main enters a sandbox that forbids opening a file or a socket (FreeBSD Capsicum),
// and every read leases one of them. A read never opens a connection while one opened here is free; it opens one only
// to replace a connection it had to close, which fails inside such a sandbox. One reader per thread that reads (one per
// worker shard), each leased for one read and given back with its transaction ended. Thread-safe.
class SnapshotReaderPool final
{
public:
    // Reads the database `store` names (its backend and location only; none of its rows). An in-memory store has no
    // database: nothing is opened and every read finds no room.
    SnapshotReaderPool(PersistentStore const& store, std::uint32_t readers);
    SnapshotReaderPool(SnapshotReaderPool const&) = delete;
    auto operator=(SnapshotReaderPool const&) -> SnapshotReaderPool& = delete;
    SnapshotReaderPool(SnapshotReaderPool&&) = delete;
    auto operator=(SnapshotReaderPool&&) -> SnapshotReaderPool& = delete;
    ~SnapshotReaderPool() = default;

    // Every room ID, from one statement. nullopt when the read fails.
    [[nodiscard]] auto room_ids() -> std::optional<std::vector<std::string>>;
    // One room as `load_room_snapshot` reads it, in one read transaction. `after_table` is a test seam.
    [[nodiscard]] auto room_snapshot(std::string_view room_id,
                                     std::function<void(std::string_view)> const& after_table = {})
        -> std::optional<RoomReloadSnapshot>;

    // Readers opened when the pool was built.
    [[nodiscard]] auto readers_opened_at_start() const noexcept -> std::uint32_t;
    // Connections ever opened, those at start included: a test proves a read opened none with it.
    [[nodiscard]] auto connections_opened() const noexcept -> std::uint64_t;

private:
    PersistentStoreBackend backend_;
    std::string sqlite_path_;
    std::string postgresql_conninfo_;
    std::string postgresql_runtime_role_;
    ConnectionPool<SqliteConnection> sqlite_;
    ConnectionPool<PostgresqlConnection> postgresql_;
    std::uint32_t readers_opened_at_start_{0U};
};

} // namespace merovingian::database
