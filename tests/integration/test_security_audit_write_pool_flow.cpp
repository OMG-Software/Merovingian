// SPDX-License-Identifier: GPL-3.0-or-later

// DB-7 (29 Sep 2026 audit): every persisted write opened a fresh database
// connection (SQLite open with its path checks, or a PostgreSQL connect and
// SET ROLE) while the runtime mutex was usually held. Writes now reuse at most
// database.pool_size connections on PostgreSQL (ADR-0154) and one on SQLite
// (ADR-0834).

#include "../support/TempDirectory.hpp"
#include "merovingian/database/ExaminedRows.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/PreparedStatement.hpp"
#include "merovingian/database/PostgresqlStore.hpp"
#include "merovingian/database/SqliteConnectionDeleter.hpp"
#include "merovingian/database/SqliteWritePool.hpp"

#include <catch2/catch_test_macros.hpp>
#include <libpq-fe.h>
#include <sqlite3.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <tuple>
#include <vector>

namespace
{

constexpr auto writers = 64U;
constexpr auto limit = std::uint32_t{4U};
// SQLite's busy handler gives up after 5 s (busy_timeout_ms in SqliteStore.cpp);
// a write held this long would outlast it by 2 s.
constexpr auto longer_than_sqlite_busy_timeout = std::chrono::milliseconds{7000};

// A plain read-write connection to the store's file, for a test that holds
// SQLite's write lock itself. Opened by SQLite, as ADR-0157 requires.
[[nodiscard]] auto open_raw_writer(std::filesystem::path const& path)
    -> std::optional<merovingian::database::SqliteConnection>
{
    auto* raw = static_cast<sqlite3*>(nullptr);
    if (sqlite3_open_v2(path.string().c_str(), &raw, SQLITE_OPEN_READWRITE, nullptr) != SQLITE_OK)
    {
        sqlite3_close(raw);
        return std::nullopt;
    }
    return merovingian::database::SqliteConnection{raw};
}

[[nodiscard]] auto run_sql(merovingian::database::SqliteConnection const& connection, char const* sql) -> bool
{
    return sqlite3_exec(connection.get(), sql, nullptr, nullptr, nullptr) == SQLITE_OK;
}

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

// SQLite runs one write at a time, so its writes share one connection whatever
// database.pool_size allows (ADR-0834).
SCENARIO("DB-7 concurrent writes to SQLite share one connection, whatever database.pool_size allows",
         "[db7][integration][database]")
{
    GIVEN("a real SQLite store whose write connections database.pool_size would limit to four")
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

            THEN("every write is durable and one connection was opened for all of them")
            {
                CHECK(committed == writers);
                CHECK(merovingian::database::write_connections_opened(store) == 1U);
                auto const reopened = merovingian::database::open_sqlite_persistent_store(path.string());
                REQUIRE(reopened.ok);
                CHECK(reopened.store.rooms.size() == writers);
            }
        }
    }
}

// SQLite's lock wait is a busy handler that polls, backing off to every 100 ms,
// and gives up after 5 s. A second write connection of this process waiting for
// the first one's lock polls against it, and is refused if the first holds the
// lock for longer: a single slow write, or one connection committing back to back
// (every journal and database sync runs under EXCLUSIVE), which is how the DB-7
// scenario above lost three writes under load on 2026-11-17 (ADR-0834).
SCENARIO("A SQLite write waits for another write of this process for longer than SQLite's busy timeout",
         "[db7][integration][database]")
{
    GIVEN("a real SQLite store allowed four write connections, one of whose writes holds SQLite's write lock")
    {
        auto const directory = TemporaryDirectory{};
        auto const path = directory.path() / "db7-held.sqlite3";
        auto opened = merovingian::database::open_sqlite_persistent_store(path.string());
        REQUIRE(opened.ok);
        auto& store = opened.store;
        merovingian::database::set_write_connection_limit(store, limit);
        REQUIRE(store.sqlite_write_pool != nullptr);
        // The held write leases a slot of the store's own pool, as a write of the
        // store does, but on a connection this test drives.
        auto held = store.sqlite_write_pool->pool.acquire(
            [&path] {
                return open_raw_writer(path);
            },
            [](merovingian::database::SqliteConnection const&) {
                return true;
            });
        REQUIRE(held.has_value());
        held->discard();
        REQUIRE(run_sql(held->get(), "BEGIN IMMEDIATE"));
        REQUIRE(run_sql(held->get(), "INSERT INTO rooms (room_id, creator_user_id, directory_public) VALUES "
                                     "('!db7-held:example.org', '@db7:example.org', 'false')"));

        WHEN("a second write starts and the first commits only after SQLite's busy timeout has passed")
        {
            auto second = std::async(std::launch::async, [&store] {
                return merovingian::database::commit_persistent_transaction(store,
                                                                            {insert_room("!db7-waiting:example.org")});
            });
            std::this_thread::sleep_for(longer_than_sqlite_busy_timeout);
            auto const first_committed = run_sql(held->get(), "COMMIT");
            held.reset();
            auto const second_committed = second.get();

            THEN("the second write waited for the first instead of being refused, and both are durable")
            {
                CHECK(first_committed);
                CHECK(second_committed);
                auto const reopened = merovingian::database::open_sqlite_persistent_store(path.string());
                REQUIRE(reopened.ok);
                CHECK(reopened.store.rooms.size() == 2U);
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
