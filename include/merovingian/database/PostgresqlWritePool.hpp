// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/PostgresqlConnection.hpp"
#include "merovingian/database/connection_pool.hpp"

#include <cstdint>

namespace merovingian::database::detail
{

struct PostgresqlWritePool final
{
    explicit PostgresqlWritePool(std::uint32_t limit)
        : pool{limit}
    {
    }
    ConnectionPool<PostgresqlConnection> pool;
};

} // namespace merovingian::database::detail
