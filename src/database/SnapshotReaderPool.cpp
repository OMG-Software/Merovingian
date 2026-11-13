// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/database/SnapshotReaderPool.hpp"

#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/SnapshotReaderConnections.hpp"
#include "merovingian/observability/SingleLog.hpp"

#include <algorithm>
#include <string>
#include <utility>
#include <vector>

namespace merovingian::database
{

namespace
{

    [[nodiscard]] auto sqlite_reusable(SqliteConnection const& /*connection*/) -> bool
    {
        // A SQLite handle stays usable after a failed read: the read transaction has ended either way.
        return true;
    }

    [[nodiscard]] auto postgresql_reusable(PostgresqlConnection& connection) -> bool
    {
        return connection.reusable();
    }

    // Opens `readers` connections now by holding that many leases at once, then gives them all back as idle.
    template <typename Connection, typename Open, typename Reusable>
    [[nodiscard]] auto open_readers(ConnectionPool<Connection>& pool, std::uint32_t readers, Open const& open,
                                    Reusable const& reusable) -> std::uint32_t
    {
        auto held = std::vector<typename ConnectionPool<Connection>::Lease>{};
        held.reserve(readers);
        for (auto index = std::uint32_t{0U}; index < readers; ++index)
        {
            auto lease = pool.acquire(open, reusable);
            if (!lease.has_value())
            {
                break;
            }
            held.push_back(std::move(*lease));
        }
        return static_cast<std::uint32_t>(held.size());
    }

    // What `load_room_snapshot` does with a backend's answer: the snapshot names the room it was asked for, and a
    // failed read is logged with the room.
    [[nodiscard]] auto named_snapshot(std::optional<RoomReloadSnapshot> snapshot, std::string_view room_id)
        -> std::optional<RoomReloadSnapshot>
    {
        if (!snapshot.has_value())
        {
            LOG_WARNING("Federation worker store: could not read room_id=" + std::string{room_id});
            return snapshot;
        }
        snapshot->room_id = std::string{room_id};
        return snapshot;
    }

} // namespace

SnapshotReaderPool::SnapshotReaderPool(PersistentStore const& store, std::uint32_t readers)
    : backend_{store.backend}
    , sqlite_path_{store.sqlite_path}
    , postgresql_conninfo_{store.postgresql_conninfo}
    , postgresql_runtime_role_{store.postgresql_runtime_role}
    , sqlite_{std::max(readers, std::uint32_t{1U})}
    , postgresql_{std::max(readers, std::uint32_t{1U})}
{
    auto const wanted = std::max(readers, std::uint32_t{1U});
    if (backend_ == PersistentStoreBackend::sqlite)
    {
        readers_opened_at_start_ = open_readers(
            sqlite_, wanted,
            [this]() {
                return detail::open_sqlite_snapshot_reader(sqlite_path_);
            },
            sqlite_reusable);
    }
    else if (backend_ == PersistentStoreBackend::postgresql)
    {
        readers_opened_at_start_ = open_readers(
            postgresql_, wanted,
            [this]() {
                return detail::open_postgresql_snapshot_reader(postgresql_conninfo_, postgresql_runtime_role_);
            },
            postgresql_reusable);
    }
    else
    {
        return;
    }
    if (readers_opened_at_start_ < wanted)
    {
        // Each read opens what is missing instead; that works unless main is inside a sandbox that forbids it.
        LOG_WARNING("Federation worker store: opened " + std::to_string(readers_opened_at_start_) + " of " +
                    std::to_string(wanted) + " database readers at start");
    }
}

auto SnapshotReaderPool::room_ids() -> std::optional<std::vector<std::string>>
{
    if (backend_ == PersistentStoreBackend::sqlite)
    {
        auto lease = sqlite_.acquire(
            [this]() {
                return detail::open_sqlite_snapshot_reader(sqlite_path_);
            },
            sqlite_reusable);
        if (!lease.has_value())
        {
            return std::nullopt;
        }
        return detail::load_room_ids_from_sqlite_connection(lease->get());
    }
    if (backend_ == PersistentStoreBackend::postgresql)
    {
        auto lease = postgresql_.acquire(
            [this]() {
                return detail::open_postgresql_snapshot_reader(postgresql_conninfo_, postgresql_runtime_role_);
            },
            postgresql_reusable);
        if (!lease.has_value())
        {
            return std::nullopt;
        }
        auto room_ids = detail::load_room_ids_from_postgresql_connection(lease->get());
        if (!lease->get().reusable())
        {
            lease->discard();
        }
        return room_ids;
    }
    // An in-memory server has no database to list: its workers start empty.
    return std::vector<std::string>{};
}

auto SnapshotReaderPool::room_snapshot(std::string_view room_id,
                                       std::function<void(std::string_view)> const& after_table)
    -> std::optional<RoomReloadSnapshot>
{
    if (backend_ == PersistentStoreBackend::sqlite)
    {
        auto lease = sqlite_.acquire(
            [this]() {
                return detail::open_sqlite_snapshot_reader(sqlite_path_);
            },
            sqlite_reusable);
        if (!lease.has_value())
        {
            return std::nullopt;
        }
        return named_snapshot(detail::load_room_snapshot_from_sqlite_connection(lease->get(), room_id, after_table),
                              room_id);
    }
    if (backend_ == PersistentStoreBackend::postgresql)
    {
        auto lease = postgresql_.acquire(
            [this]() {
                return detail::open_postgresql_snapshot_reader(postgresql_conninfo_, postgresql_runtime_role_);
            },
            postgresql_reusable);
        if (!lease.has_value())
        {
            return std::nullopt;
        }
        auto snapshot = detail::load_room_snapshot_from_postgresql_connection(lease->get(), room_id, after_table);
        if (!lease->get().reusable())
        {
            lease->discard();
        }
        return named_snapshot(std::move(snapshot), room_id);
    }
    // Nothing to read from memory: the worker keeps what it holds, as `load_room_snapshot` answers for a memory store.
    auto unchanged = RoomReloadSnapshot{};
    unchanged.nothing_to_apply = true;
    return unchanged;
}

auto SnapshotReaderPool::readers_opened_at_start() const noexcept -> std::uint32_t
{
    return readers_opened_at_start_;
}

auto SnapshotReaderPool::connections_opened() const noexcept -> std::uint64_t
{
    return sqlite_.opened_total() + postgresql_.opened_total();
}

} // namespace merovingian::database
