// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <tuple>

#include <sqlite3.h>

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

// R02: makes every INSERT into one table of the server's database file fail
// from a second connection, so the server's own transaction aborts and rolls
// back exactly as a failed commit would. A non-empty `when` limits the fault to
// rows matching that SQL condition over NEW (for example
// "NEW.pending_txn_id = '0'"), so one of several writes to the same table can
// be failed on its own. clear() lifts the fault so a client retry can succeed;
// the destructor lifts it too.
class SqliteInsertFault final
{
public:
    SqliteInsertFault(std::filesystem::path const& path, std::string_view table, std::string_view name,
                      std::string_view when = {})
        : drop_sql_{"DROP TRIGGER IF EXISTS " + std::string{name}}
    {
        auto* raw_connection = static_cast<sqlite3*>(nullptr);
        auto const status = sqlite3_open(path.string().c_str(), &raw_connection);
        connection_.reset(raw_connection);
        REQUIRE(status == SQLITE_OK);
        REQUIRE(connection_ != nullptr);
        auto const condition = when.empty() ? std::string{} : " WHEN " + std::string{when};
        REQUIRE(execute("CREATE TRIGGER " + std::string{name} + " BEFORE INSERT ON " + std::string{table} + condition +
                        " BEGIN SELECT RAISE(ABORT, 'injected write failure'); END"));
        active_ = true;
    }

    SqliteInsertFault(SqliteInsertFault const&) = delete;
    auto operator=(SqliteInsertFault const&) -> SqliteInsertFault& = delete;
    SqliteInsertFault(SqliteInsertFault&&) = delete;
    auto operator=(SqliteInsertFault&&) -> SqliteInsertFault& = delete;

    ~SqliteInsertFault()
    {
        if (active_)
        {
            std::ignore = execute(drop_sql_);
        }
    }

    auto clear() -> void
    {
        REQUIRE(execute(drop_sql_));
        active_ = false;
    }

private:
    [[nodiscard]] auto execute(std::string const& sql) const -> bool
    {
        return sqlite3_exec(connection_.get(), sql.c_str(), nullptr, nullptr, nullptr) == SQLITE_OK;
    }

    std::unique_ptr<sqlite3, SqliteCloser> connection_{};
    std::string drop_sql_{};
    bool active_{false};
};

} // namespace merovingian::tests
