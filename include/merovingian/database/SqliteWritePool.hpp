// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/ConnectionPool.hpp"
#include "merovingian/database/SqliteConnectionDeleter.hpp"

#include <cstdint>

namespace merovingian::database::detail
{

// ADR-0834: one SQLite write connection, whatever database.pool_size says.
// SQLite runs one write transaction at a time; a second connection of this
// process would wait for the first's lock in SQLite's polling busy handler,
// lose to its back-to-back commits and be refused after 5 s. Writers wait in
// the pool instead, without a time limit.
struct SqliteWritePool final
{
    static constexpr auto connection_limit = std::uint32_t{1U};

    SqliteWritePool()
        : pool{connection_limit}
    {
    }
    ConnectionPool<SqliteConnection> pool;
};

} // namespace merovingian::database::detail
