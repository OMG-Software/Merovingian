// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <memory>

struct pg_conn;

namespace merovingian::database
{

struct PostgresqlConnectionDeleter final
{
    auto operator()(pg_conn* connection) const noexcept -> void;
};

using PostgresqlConnectionPtr = std::unique_ptr<pg_conn, PostgresqlConnectionDeleter>;

} // namespace merovingian::database
