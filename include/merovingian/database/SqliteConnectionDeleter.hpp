// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <memory>

struct sqlite3;

namespace merovingian::database
{

struct SqliteConnectionDeleter final
{
    auto operator()(sqlite3* connection) const noexcept -> void;
};

using SqliteConnection = std::unique_ptr<sqlite3, SqliteConnectionDeleter>;

} // namespace merovingian::database
