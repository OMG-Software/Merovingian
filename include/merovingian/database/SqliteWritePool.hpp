// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/ConnectionPool.hpp"
#include "merovingian/database/SqliteConnectionDeleter.hpp"

#include <cstdint>

namespace merovingian::database::detail
{

struct SqliteWritePool final
{
    explicit SqliteWritePool(std::uint32_t limit)
        : pool{limit}
    {
    }
    ConnectionPool<SqliteConnection> pool;
};

} // namespace merovingian::database::detail
