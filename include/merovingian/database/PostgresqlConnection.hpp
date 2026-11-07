// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/DatabaseExecutor.hpp"
#include "merovingian/database/PreparedStatement.hpp"
#include "merovingian/database/QueryResult.hpp"

#include <memory>
#include <string_view>
#include <vector>

namespace merovingian::database
{

struct PostgresqlConnectionHandle;
struct PostgresqlConnectionOpenResult;

class PostgresqlConnection final : public DatabaseExecutor
{
public:
    PostgresqlConnection() noexcept;
    PostgresqlConnection(PostgresqlConnection const& other) = delete;
    auto operator=(PostgresqlConnection const& other) -> PostgresqlConnection& = delete;
    PostgresqlConnection(PostgresqlConnection&& other) noexcept;
    auto operator=(PostgresqlConnection&& other) noexcept -> PostgresqlConnection&;
    ~PostgresqlConnection() override;

    [[nodiscard]] auto open() const noexcept -> bool;
    [[nodiscard]] auto execute(PreparedStatement const& statement) -> QueryResult override;
    [[nodiscard]] auto execute_transaction(std::vector<PreparedStatement> const& statements) -> bool;
    // DB-7: open, idle and not closed by the server, so it can serve another
    // transaction from the write pool.
    [[nodiscard]] auto reusable() noexcept -> bool;

private:
    friend auto open_postgresql_connection(std::string_view conninfo) -> PostgresqlConnectionOpenResult;

    explicit PostgresqlConnection(std::unique_ptr<PostgresqlConnectionHandle> handle) noexcept;

    std::unique_ptr<PostgresqlConnectionHandle> handle_{};
};

} // namespace merovingian::database
