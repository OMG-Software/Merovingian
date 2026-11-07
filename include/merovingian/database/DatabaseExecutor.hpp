// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/QueryResult.hpp"

namespace merovingian::database
{

struct PreparedStatement;

class DatabaseExecutor
{
public:
    DatabaseExecutor() = default;
    DatabaseExecutor(DatabaseExecutor const& other) = delete;
    auto operator=(DatabaseExecutor const& other) -> DatabaseExecutor& = delete;
    DatabaseExecutor(DatabaseExecutor&& other) noexcept = default;
    auto operator=(DatabaseExecutor&& other) noexcept -> DatabaseExecutor& = default;
    virtual ~DatabaseExecutor() = default;

    [[nodiscard]] virtual auto execute(PreparedStatement const& statement) -> QueryResult = 0;
};

} // namespace merovingian::database
