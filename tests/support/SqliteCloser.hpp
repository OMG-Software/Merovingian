// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <sqlite3.h>

#include <tuple>

namespace merovingian::tests
{

struct SqliteCloser final
{
    auto operator()(sqlite3* connection) const noexcept -> void
    {
        if (connection != nullptr)
        {
            std::ignore = sqlite3_close(connection);
        }
    }
};

} // namespace merovingian::tests
