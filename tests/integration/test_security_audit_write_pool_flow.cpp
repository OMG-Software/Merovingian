// SPDX-License-Identifier: GPL-3.0-or-later

// DB-7 (29 Sep 2026 audit): every persisted write opened a fresh database
// connection (SQLite open with its path checks, or a PostgreSQL connect and
// SET ROLE) while the runtime mutex was usually held. Writes now reuse at most
// database.pool_size connections (ADR-0154).

#include "../support/temp_directory.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/database/postgresql_store.hpp"
#include "merovingian/database/statement.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <future>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <tuple>
#include <vector>

#include <libpq-fe.h>

namespace
{

constexpr auto writers = 64U;
constexpr auto limit = std::uint32_t{4U};

[[nodiscard]] auto insert_room(std::string const& room_id) -> merovingian::database::PreparedStatement
{
    return {
        "insert_room",
        "INSERT INTO rooms (room_id, creator_user_id, directory_public) VALUES ($1, $2, $3)",
        {{room_id, false}, {"@db7:example.org", false}, {"false", false}}
    };
}

// Commits one INSERT per room from `writers` threads at once; returns how many
// commits succeeded. No Catch assertion runs on a worker thread.
[[nodiscard]] auto commit_concurrently(merovingian::database::PersistentStore& store, std::string const& prefix)
    -> std::size_t
{
    auto futures = std::vector<std::future<bool>>{};
    futures.reserve(writers);
    for (auto i = 0U; i < writers; ++i)
    {
        futures.push_back(std::async(std::launch::async, [&store, room = prefix + std::to_string(i)] {
            return merovingian::database::commit_persistent_transaction(store, {insert_room(room)});
        }));
    }
    auto committed = std::size_t{0U};
    for (auto& future : futures)
    {
        committed += future.get() ? 1U : 0U;
    }
    return committed;
}

class TemporaryDirectory final
{
public:
    TemporaryDirectory()
        : path_{merovingian::tests::temporary_directory() /
                ("merovingian-db7-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()))}
    {
        std::filesystem::create_directories(path_);
        std::filesystem::permissions(path_, std::filesystem::perms::owner_all, std::filesystem::perm_options::replace);
    }
    TemporaryDirectory(TemporaryDirectory const&) = delete;
    auto operator=(TemporaryDirectory const&) -> TemporaryDirectory& = delete;
    TemporaryDirectory(TemporaryDirectory&&) = delete;
    auto operator=(TemporaryDirectory&&) -> TemporaryDirectory& = delete;
    ~TemporaryDirectory()
    {
        auto ignored = std::error_code{};
        std::filesystem::remove_all(path_, ignored);
    }
    [[nodiscard]] auto path() const -> std::filesystem::path const&
    {
        return path_;
    }

private:
    std::filesystem::path path_;
};

[[nodiscard]] auto postgresql_uri() -> std::string
{
    auto const* value = std::getenv("MEROVINGIAN_TEST_POSTGRESQL_URI");
    return value == nullptr ? std::string{} : std::string{value};
}

struct PgFinish final
{
    auto operator()(PGconn* connection) const noexcept -> void
    {
        PQfinish(connection);
    }
};

struct PgClear final
{
    auto operator()(PGresult* result) const noexcept -> void
    {
        PQclear(result);
    }
};

// Terminates every other backend of this database user, as a server restart
// or an idle-connection reaper would, and waits until they have gone: the
// pooled connections are then closed by the server, not dying mid-use.
auto terminate_other_backends(std::string const& uri) -> bool
{
    auto const connection = std::unique_ptr<PGconn, PgFinish>{PQconnectdb(uri.c_str())};
    if (connection == nullptr || PQstatus(connection.get()) != CONNECTION_OK)
    {
        return false;
    }
    auto constexpr others = "FROM pg_stat_activity WHERE usename = current_user AND pid <> pg_backend_pid() AND "
                            "datname = current_database()";
    auto const terminated = std::unique_ptr<PGresult, PgClear>{
        PQexec(connection.get(), (std::string{"SELECT pg_terminate_backend(pid) "} + others).c_str())};
    if (terminated == nullptr || PQresultStatus(terminated.get()) != PGRES_TUPLES_OK)
    {
        return false;
    }
    auto const deadline = std::chrono::steady_clock::now() + std::chrono::seconds{10};
    while (std::chrono::steady_clock::now() < deadline)
    {
        auto const remaining = std::unique_ptr<PGresult, PgClear>{
            PQexec(connection.get(), (std::string{"SELECT count(*) "} + others).c_str())};
        if (remaining != nullptr && PQresultStatus(remaining.get()) == PGRES_TUPLES_OK &&
            std::string_view{PQgetvalue(remaining.get(), 0, 0)} == "0")
        {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{50});
    }
    return false;
}

} // namespace

SCENARIO("DB-7 concurrent writes to SQLite reuse at most database.pool_size connections",
         "[db7][integration][database]")
{
    GIVEN("a real SQLite store whose write connections are limited to four")
    {
        auto const directory = TemporaryDirectory{};
        auto const path = directory.path() / "db7.sqlite3";
        auto opened = merovingian::database::open_sqlite_persistent_store(path.string());
        REQUIRE(opened.ok);
        auto& store = opened.store;
        merovingian::database::set_write_connection_limit(store, limit);

        WHEN("64 writers commit at once")
        {
            auto const committed = commit_concurrently(store, "!db7-sqlite-");

            THEN("every write is durable and no more than four connections were ever opened for them")
            {
                CHECK(committed == writers);
                CHECK(merovingian::database::write_connections_opened(store) <= limit);
                auto const reopened = merovingian::database::open_sqlite_persistent_store(path.string());
                REQUIRE(reopened.ok);
                CHECK(reopened.store.rooms.size() == writers);
            }
        }
    }
}

SCENARIO("DB-7 concurrent writes to PostgreSQL reuse at most database.pool_size connections, and replace dead ones",
         "[db7][integration][database][postgresql]")
{
    GIVEN("a PostgreSQL store whose write connections are limited to four")
    {
        auto const uri = postgresql_uri();
        if (uri.empty())
        {
            SUCCEED("skipped: MEROVINGIAN_TEST_POSTGRESQL_URI is not set");
            return;
        }
        auto opened = merovingian::database::open_postgresql_persistent_store(uri);
        REQUIRE(opened.ok);
        auto& store = opened.store;
        merovingian::database::set_write_connection_limit(store, limit);
        auto const prefix =
            "!db7-pg-" + std::to_string(std::chrono::system_clock::now().time_since_epoch().count()) + "-";

        WHEN("64 writers commit at once, the server drops every pooled connection, and 64 more commit")
        {
            auto const first = commit_concurrently(store, prefix + "a-");
            auto const opened_before = merovingian::database::write_connections_opened(store);
            REQUIRE(terminate_other_backends(uri));
            auto const second = commit_concurrently(store, prefix + "b-");

            THEN("every write succeeds, at most four connections served each round, and dead ones were replaced")
            {
                CHECK(first == writers);
                CHECK(opened_before <= limit);
                CHECK(second == writers);
                CHECK(merovingian::database::write_connections_opened(store) <= 2U * limit);
            }
        }
    }
}
