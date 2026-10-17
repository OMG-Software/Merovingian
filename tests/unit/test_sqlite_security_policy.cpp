// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/joining_threads.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/core/file_descriptor.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/platform/landlock_hardening.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>

#include <fcntl.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

namespace
{
class DatabaseScratch final
{
public:
    DatabaseScratch()
    {
        auto pattern = (std::filesystem::temp_directory_path() / "merov-db-security-XXXXXX").string();
        auto const* made = ::mkdtemp(pattern.data());
        if (made == nullptr)
        {
            throw std::runtime_error{"temporary directory unavailable"};
        }
        path = made;
    }
    ~DatabaseScratch()
    {
        auto ec = std::error_code{};
        std::filesystem::remove_all(path, ec);
    }
    std::filesystem::path path;
};
} // namespace
SCENARIO("Production SQLite worker bootstrap cannot persist changes", "[database][iso4]")
{
    GIVEN("main's initialized SQLite database")
    {
        auto scratch = DatabaseScratch{};
        auto const path = (scratch.path / "store.db").string();
        auto main = merovingian::database::open_sqlite_persistent_store(path);
        REQUIRE(main.ok);
        REQUIRE(merovingian::database::store_room(main.store, {"!original:example.org", "@a:example.org"}));
        auto database = merovingian::config::DatabaseConfig{};
        database.backend = merovingian::config::DatabaseBackend::sqlite;
        database.sqlite_path = path;
        auto const config = merovingian::config::Config{merovingian::config::ServerConfig{},
                                                        merovingian::config::ListenersConfig{},
                                                        database,
                                                        merovingian::config::SecurityConfig{},
                                                        merovingian::config::ClientRateLimitsConfig{},
                                                        merovingian::config::LogModulesConfig{}};
        WHEN("the production worker load profile bootstraps a snapshot")
        {
            auto worker = merovingian::homeserver::bootstrap_local_database(
                config, {}, merovingian::database::TableLoadProfile::federation_worker);
            THEN("reads work and writes fail without affecting main's write path")
            {
                REQUIRE(worker.opened);
                REQUIRE(worker.persistent_store.rooms.size() == 1U);
                REQUIRE_FALSE(merovingian::database::store_room(worker.persistent_store,
                                                                {"!worker:example.org", "@a:example.org"}));
                REQUIRE(merovingian::database::store_room(main.store, {"!main:example.org", "@a:example.org"}));
                auto const reopened = merovingian::database::open_sqlite_persistent_store(path);
                REQUIRE(reopened.ok);
                REQUIRE(reopened.store.rooms.size() == 2U);
            }
        }
    }
}
#if defined(__linux__)
SCENARIO("Landlocked production SQLite worker cannot open main's database for writing",
         "[database][iso4][iso4_landlock]")
{
    GIVEN("main's initialized SQLite database and the real kernel Landlock API")
    {
        auto const ops = merovingian::platform::LandlockHardeningOps{};
        if (ops.query_abi_version() < 1)
        {
            SKIP("kernel has no Landlock support");
        }
        auto scratch = DatabaseScratch{};
        auto const path = (scratch.path / "store.db").string();
        auto main = merovingian::database::open_sqlite_persistent_store(path);
        REQUIRE(main.ok);
        REQUIRE(merovingian::database::store_room(main.store, {"!original:example.org", "@a:example.org"}));
        auto database = merovingian::config::DatabaseConfig{};
        database.backend = merovingian::config::DatabaseBackend::sqlite;
        database.sqlite_path = path;
        auto const config = merovingian::config::Config{merovingian::config::ServerConfig{},
                                                        merovingian::config::ListenersConfig{},
                                                        database,
                                                        merovingian::config::SecurityConfig{},
                                                        merovingian::config::ClientRateLimitsConfig{},
                                                        merovingian::config::LogModulesConfig{}};
        WHEN("a child installs the exact worker filesystem policy before production bootstrap")
        {
            auto const pid = ::fork();
            REQUIRE(pid >= 0);
            if (pid == 0)
            {
                auto const hardened = merovingian::platform::apply_worker_landlock(
                    merovingian::platform::build_worker_landlock_rules(config), false);
                if (!hardened.applied)
                {
                    ::_exit(10);
                }
                auto write = merovingian::core::FileDescriptor{::open(path.c_str(), O_RDWR | O_CLOEXEC)};
                if (write.valid())
                {
                    ::_exit(11);
                }
                auto worker = merovingian::homeserver::bootstrap_local_database(
                    config, {}, merovingian::database::TableLoadProfile::federation_worker);
                if (!worker.opened || worker.persistent_store.rooms.size() != 1U)
                {
                    ::_exit(12);
                }
                if (merovingian::database::store_room(worker.persistent_store,
                                                      {"!worker:example.org", "@a:example.org"}))
                {
                    ::_exit(13);
                }
                ::_exit(0);
            }
            auto status = int{};
            REQUIRE(::waitpid(pid, &status, 0) == pid);
            THEN("the worker remains functional but even a raw writable open is denied")
            {
                REQUIRE(WIFEXITED(status));
                REQUIRE(WEXITSTATUS(status) == 0);
                REQUIRE(merovingian::database::store_room(main.store, {"!main:example.org", "@a:example.org"}));
            }
        }
    }
}
#endif
SCENARIO("SQLite creation is private under a permissive process umask", "[database][db10][iso6]")
{
    GIVEN("a missing database directory and an existing operator directory")
    {
        auto scratch = DatabaseScratch{};
        auto const existing = scratch.path / "existing";
        std::filesystem::create_directory(existing);
        REQUIRE(::chmod(existing.c_str(), 0750) == 0);
        auto const path = scratch.path / "new" / "nested" / "store.db";
        WHEN("a store is created while the ambient umask permits world access")
        {
            auto const old = ::umask(0000);
            auto const opened = merovingian::database::open_sqlite_persistent_store(path.string());
            std::ignore = ::umask(old);
            THEN("new database and directories are private and preexisting directory permissions are untouched")
            {
                REQUIRE(opened.ok);
                struct stat status{};
                REQUIRE(::stat(path.c_str(), &status) == 0);
                REQUIRE((status.st_mode & 0777) == 0600);
                REQUIRE(::stat(path.parent_path().c_str(), &status) == 0);
                REQUIRE((status.st_mode & 0777) == 0700);
                REQUIRE(::stat(path.parent_path().parent_path().c_str(), &status) == 0);
                REQUIRE((status.st_mode & 0777) == 0700);
                REQUIRE(merovingian::database::open_sqlite_persistent_store((existing / "store.db").string()).ok);
                REQUIRE(::stat(existing.c_str(), &status) == 0);
                REQUIRE((status.st_mode & 0777) == 0750);
            }
        }
    }
}
SCENARIO("SQLite refuses a symlinked database file without changing its target", "[database][db10]")
{
    GIVEN("a database and a symlink to it")
    {
        auto scratch = DatabaseScratch{};
        auto const target = scratch.path / "target.db";
        REQUIRE(merovingian::database::open_sqlite_persistent_store(target.string()).ok);
        auto const alias = scratch.path / "alias.db";
        std::filesystem::create_symlink(target, alias);
        WHEN("the symlink is opened")
        {
            THEN("it is refused and the original database remains usable")
            {
                REQUIRE_FALSE(merovingian::database::open_sqlite_persistent_store(alias.string()).ok);
                REQUIRE(merovingian::database::open_sqlite_persistent_store(target.string()).ok);
            }
        }
    }
}
SCENARIO("SQLite follows an operator's existing symlinked data directory", "[database][db10]")
{
    // PR #509 review: refusing every symlinked ancestor broke common layouts
    // (/var/lib/merovingian -> /data/merovingian, Fedora Atomic's /home ->
    // /var/home). A directory that already exists belongs to the operator; only
    // the database file itself must not be a symlink.
    GIVEN("a data directory reached through a symlink, holding one database")
    {
        auto scratch = DatabaseScratch{};
        auto const real = scratch.path / "real";
        std::filesystem::create_directory(real);
        REQUIRE(merovingian::database::open_sqlite_persistent_store((real / "store.db").string()).ok);
        auto const linked = scratch.path / "linked";
        std::filesystem::create_directory_symlink(real, linked);
        WHEN("a database is opened through the symlink, and another created in new directories beneath it")
        {
            auto const existing = merovingian::database::open_sqlite_persistent_store((linked / "store.db").string());
            auto const nested = linked / "new" / "nested" / "other.db";
            auto const created = merovingian::database::open_sqlite_persistent_store(nested.string());
            THEN("both open, in the real directory, and the new directories and file are private")
            {
                REQUIRE(existing.ok);
                REQUIRE(created.ok);
                REQUIRE(std::filesystem::is_regular_file(real / "new" / "nested" / "other.db"));
                struct stat status{};
                REQUIRE(::stat((real / "new").c_str(), &status) == 0);
                REQUIRE((status.st_mode & 0777) == 0700);
                REQUIRE(::stat((real / "new" / "nested" / "other.db").c_str(), &status) == 0);
                REQUIRE((status.st_mode & 0777) == 0600);
            }
        }
    }
}
namespace
{
// SQLite's RESERVED lock byte: PENDING_BYTE (0x40000000) + 1. A writer holds
// it from BEGIN IMMEDIATE to COMMIT; while it is held, no other process may
// treat a rollback journal as hot.
constexpr auto sqlite_reserved_byte = off_t{0x40000001};

// Whether another process sees a write lock on the RESERVED byte. POSIX
// record locks are per process, so the probe must run in a child.
[[nodiscard]] auto other_process_sees_reserved_lock(std::filesystem::path const& path) -> bool
{
    auto const pid = ::fork();
    if (pid == 0)
    {
        auto const fd = ::open(path.c_str(), O_RDWR | O_CLOEXEC);
        // `struct`: the BSDs also declare a flock() function.
        struct flock probe{};
        probe.l_type = F_WRLCK;
        probe.l_whence = SEEK_SET;
        probe.l_start = sqlite_reserved_byte;
        probe.l_len = 1;
        auto const held = fd >= 0 && ::fcntl(fd, F_GETLK, &probe) == 0 && probe.l_type != F_UNLCK;
        ::_exit(held ? 0 : 1);
    }
    auto status = 0;
    return pid > 0 && ::waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

struct RawSqlite final
{
    explicit RawSqlite(std::filesystem::path const& path)
    {
        auto* raw = static_cast<sqlite3*>(nullptr);
        std::ignore = sqlite3_open_v2(path.c_str(), &raw, SQLITE_OPEN_READWRITE, nullptr);
        handle.reset(raw);
    }
    struct Close final
    {
        auto operator()(sqlite3* db) const noexcept -> void
        {
            std::ignore = sqlite3_close(db);
        }
    };
    std::unique_ptr<sqlite3, Close> handle;
};
} // namespace
SCENARIO("Opening a SQLite connection never releases another connection's write lock", "[database][sqlite-locks]")
{
    // Closing any descriptor of a file drops every POSIX lock the process
    // holds on it. Opening a connection used to open and close the database
    // file itself, so a write transaction on another connection silently lost
    // its RESERVED lock: another process then took its journal for a hot one
    // (the federation worker's read-only room reload failed on OpenBSD), and a
    // read-write process could roll back a transaction still in progress.
    GIVEN("a store database and a connection holding a write transaction")
    {
        auto scratch = DatabaseScratch{};
        auto const path = scratch.path / "store.db";
        REQUIRE(merovingian::database::open_sqlite_persistent_store(path.string()).ok);
        auto writer = RawSqlite{path};
        REQUIRE(writer.handle != nullptr);
        REQUIRE(sqlite3_exec(writer.handle.get(), "BEGIN IMMEDIATE", nullptr, nullptr, nullptr) == SQLITE_OK);
        REQUIRE(other_process_sees_reserved_lock(path));

        WHEN("the same process opens the database read-write")
        {
            auto const opened = merovingian::database::open_sqlite_persistent_store(path.string());

            THEN("the write transaction still holds its lock")
            {
                REQUIRE(opened.ok);
                CHECK(other_process_sees_reserved_lock(path));
            }
        }

        WHEN("the same process reads it through a read-only connection")
        {
            std::ignore = merovingian::database::detail::read_media_blob_from_sqlite(path.string(), "absent");
            std::ignore =
                merovingian::database::detail::load_room_snapshot_from_sqlite(path.string(), "!r:example.org");

            THEN("the write transaction still holds its lock")
            {
                CHECK(other_process_sees_reserved_lock(path));
            }
        }

        std::ignore = sqlite3_exec(writer.handle.get(), "ROLLBACK", nullptr, nullptr, nullptr);
    }
}
SCENARIO("A read-only SQLite connection refuses a WAL database before reading it", "[database][sqlite-locks]")
{
    GIVEN("a store database switched to WAL mode")
    {
        auto scratch = DatabaseScratch{};
        auto const path = scratch.path / "store.db";
        REQUIRE(merovingian::database::open_sqlite_persistent_store(path.string()).ok);
        {
            auto wal = RawSqlite{path};
            REQUIRE(wal.handle != nullptr);
            REQUIRE(sqlite3_exec(wal.handle.get(), "PRAGMA journal_mode = WAL", nullptr, nullptr, nullptr) ==
                    SQLITE_OK);
        }

        WHEN("it is opened read-only")
        {
            auto const opened = merovingian::database::open_sqlite_persistent_store(
                path.string(), merovingian::database::TableLoadProfile::federation_worker);

            THEN("it is refused and no shared-memory index is created")
            {
                CHECK_FALSE(opened.ok);
                CHECK_FALSE(std::filesystem::exists(scratch.path / "store.db-shm"));
            }
        }
    }
}

namespace
{
// A rollback journal that a reader takes for a hot one: present, first byte
// non-zero, and no process holding the RESERVED lock. A reader sees exactly
// this when it checks between a writer deleting its journal and dropping its
// lock (SQLite ticket #3883).
auto write_hot_looking_journal(std::filesystem::path const& journal) -> void
{
    auto stream = std::ofstream{journal, std::ios::binary};
    REQUIRE(stream.is_open());
    stream << std::string(512U, '\xd9');
    stream.close();
    auto const written = !stream.fail();
    REQUIRE(written);
}
} // namespace
SCENARIO("A read-only SQLite read outlasts a journal that only looks hot while a writer commits",
         "[database][sqlite-locks][sqlite-false-hot-journal]")
{
    // A read-write connection resolves a hot-looking journal under EXCLUSIVE;
    // a read-only one fails at once with SQLITE_READONLY_ROLLBACK, skipping the
    // busy handler. The federation worker's room reload then failed on
    // OpenBSD and the proxy fell back to main for that room.
    GIVEN("main's SQLite database holding a room, beside a journal that looks hot")
    {
        using namespace std::chrono_literals;
        auto scratch = DatabaseScratch{};
        auto const path = scratch.path / "store.db";
        auto const journal = scratch.path / "store.db-journal";
        auto const room_id = std::string{"!reload:example.org"};
        {
            auto main = merovingian::database::open_sqlite_persistent_store(path.string());
            REQUIRE(main.ok);
            REQUIRE(merovingian::database::store_room(main.store, {room_id, "@a:example.org"}));
        }
        write_hot_looking_journal(journal);

        WHEN("the journal disappears, as the committing writer's does, while a read-only room snapshot is starting")
        {
            auto snapshot = std::optional<merovingian::database::RoomReloadSnapshot>{};
            {
                auto remover = merovingian::tests::JoiningThreads{};
                remover.emplace_back([&journal] {
                    std::this_thread::sleep_for(200ms);
                    auto ignored = std::error_code{};
                    std::ignore = std::filesystem::remove(journal, ignored);
                });
                snapshot = merovingian::database::detail::load_room_snapshot_from_sqlite(path.string(), room_id);
            }

            THEN("the snapshot is read once the journal is gone")
            {
                REQUIRE(snapshot.has_value());
                REQUIRE(snapshot->room.has_value());
                CHECK(snapshot->room->room_id == room_id);
            }
        }

        WHEN("the journal disappears while the federation worker's read-only store load is starting")
        {
            auto opened = merovingian::database::PersistentStoreOpenResult{};
            {
                auto remover = merovingian::tests::JoiningThreads{};
                remover.emplace_back([&journal] {
                    std::this_thread::sleep_for(200ms);
                    auto ignored = std::error_code{};
                    std::ignore = std::filesystem::remove(journal, ignored);
                });
                opened = merovingian::database::open_sqlite_persistent_store(
                    path.string(), merovingian::database::TableLoadProfile::federation_worker);
            }

            THEN("the store loads with the room")
            {
                REQUIRE(opened.ok);
                CHECK(opened.store.rooms.size() == 1U);
            }
        }

        WHEN("the journal stays, as a crashed writer's really hot journal does")
        {
            auto const started = std::chrono::steady_clock::now();
            auto const snapshot = merovingian::database::detail::load_room_snapshot_from_sqlite(path.string(), room_id);
            auto const elapsed = std::chrono::steady_clock::now() - started;

            THEN("the read fails within a bounded time and leaves the journal for a read-write connection")
            {
                CHECK_FALSE(snapshot.has_value());
                CHECK(elapsed < 10s);
                CHECK(std::filesystem::exists(journal));
                CHECK(std::filesystem::file_size(journal) == 512U);
            }
        }
    }
}

namespace
{
[[nodiscard]] auto topic_event_json(std::string_view event_id) -> std::string
{
    return R"({"event_id":")" + std::string{event_id} +
           R"(","room_id":"!torn:example.org","sender":"@a:example.org","type":"m.room.topic","state_key":"",)"
           R"("content":{"topic":"t"}})";
}

// Whether every current-state row of a snapshot names an event in that same
// snapshot: true only for rows read from one committed state of the room.
[[nodiscard]] auto state_names_only_snapshot_events(merovingian::database::RoomReloadSnapshot const& snapshot) -> bool
{
    return std::ranges::all_of(snapshot.state, [&snapshot](auto const& entry) {
        return std::ranges::any_of(snapshot.events, [&entry](auto const& event) {
            return event.event_id == entry.event_id;
        });
    });
}
} // namespace
SCENARIO("A room snapshot reads one committed state of the room even while main commits between its reads",
         "[database][sqlite-locks][room-snapshot-consistency]")
{
    // The worker's room reload read each table in its own statement, so a
    // commit landing between the events read and the current_state read gave
    // it state naming an event its snapshot did not hold.
    GIVEN("main's SQLite database holding a room with one event that is current state")
    {
        auto scratch = DatabaseScratch{};
        auto const path = scratch.path / "store.db";
        auto const room_id = std::string{"!torn:example.org"};
        auto const first_id = std::string{"$first:example.org"};
        {
            auto main = merovingian::database::open_sqlite_persistent_store(path.string());
            REQUIRE(main.ok);
            REQUIRE(merovingian::database::store_room(main.store, {room_id, "@a:example.org"}));
            REQUIRE(merovingian::database::store_event_with_state(
                main.store,
                merovingian::database::PersistentEvent{first_id, room_id, "@a:example.org", topic_event_json(first_id),
                                                       1U, 1U},
                merovingian::database::PersistentStateEvent{room_id, "m.room.topic", "", first_id}));
        }
        auto writer = RawSqlite{path};
        REQUIRE(writer.handle != nullptr);

        WHEN("another connection commits a new event and makes it current state after the snapshot reads events")
        {
            auto inserted = false;
            auto const commit_between_reads = [&](std::string_view table) {
                if (table != "events")
                {
                    return;
                }
                auto* const db = writer.handle.get();
                auto const insert_event =
                    std::string{"INSERT INTO events (event_id, room_id, sender_user_id, json, depth, stream_ordering) "
                                "VALUES ('$second:example.org', '!torn:example.org', '@a:example.org', '"} +
                    topic_event_json("$second:example.org") + "', '2', '2')";
                REQUIRE(sqlite3_exec(db, "BEGIN IMMEDIATE", nullptr, nullptr, nullptr) == SQLITE_OK);
                inserted = sqlite3_exec(db, insert_event.c_str(), nullptr, nullptr, nullptr) == SQLITE_OK &&
                           sqlite3_exec(db,
                                        "UPDATE current_state SET event_id = '$second:example.org' WHERE room_id = "
                                        "'!torn:example.org' AND event_type = 'm.room.topic' AND state_key = ''",
                                        nullptr, nullptr, nullptr) == SQLITE_OK;
                // The commit may wait for the snapshot; that is the point.
                if (sqlite3_exec(db, "COMMIT", nullptr, nullptr, nullptr) != SQLITE_OK)
                {
                    std::ignore = sqlite3_exec(db, "ROLLBACK", nullptr, nullptr, nullptr);
                }
            };
            auto const snapshot = merovingian::database::detail::load_room_snapshot_from_sqlite(path.string(), room_id,
                                                                                                commit_between_reads);

            THEN("its current state names only events the snapshot holds")
            {
                REQUIRE(inserted);
                REQUIRE(snapshot.has_value());
                REQUIRE(snapshot->state.size() == 1U);
                CHECK(state_names_only_snapshot_events(*snapshot));
            }
        }
    }
}
