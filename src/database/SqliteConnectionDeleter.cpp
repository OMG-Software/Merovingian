// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/database/SqliteConnectionDeleter.hpp"

#include <sqlite3.h>

namespace merovingian::database
{

auto SqliteConnectionDeleter::operator()(sqlite3* connection) const noexcept -> void
{
    sqlite3_close(connection);
}

} // namespace merovingian::database
