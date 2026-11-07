// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/database/PostgresqlConnectionDeleter.hpp"

#include <libpq-fe.h>

namespace merovingian::database
{

auto PostgresqlConnectionDeleter::operator()(pg_conn* connection) const noexcept -> void
{
    PQfinish(connection);
}

} // namespace merovingian::database
