// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <merovingian/database/statement.hpp>

#include <string>
#include <vector>

namespace merovingian::database
{

struct QueryResult final
{
    bool ok{false};
    std::string error{};
    std::vector<std::vector<std::string>> rows{};
};

class DatabaseExecutor
{
public:
    DatabaseExecutor() = default;
    DatabaseExecutor(DatabaseExecutor const& other) = delete;
    auto operator=(DatabaseExecutor const& other) -> DatabaseExecutor& = delete;
    DatabaseExecutor(DatabaseExecutor&& other) noexcept = delete;
    auto operator=(DatabaseExecutor&& other) noexcept -> DatabaseExecutor& = delete;
    virtual ~DatabaseExecutor() = default;

    [[nodiscard]] virtual auto execute(PreparedStatement const& statement) -> QueryResult = 0;
};

[[nodiscard]] auto execute_validated(DatabaseExecutor& executor, PreparedStatement const& statement) -> QueryResult;

} // namespace merovingian::database
