// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/core/file_descriptor.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/platform/landlock_hardening.hpp"
#include <catch2/catch_test_macros.hpp>
#include <filesystem>
#include <string>
#include <stdexcept>
#include <cstdlib>
#include <tuple>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>

namespace {
class DatabaseScratch final {
public:
    DatabaseScratch() { auto pattern = (std::filesystem::temp_directory_path() / "merov-db-security-XXXXXX").string(); auto const* made = ::mkdtemp(pattern.data()); if (made == nullptr) { throw std::runtime_error{"temporary directory unavailable"}; } path = made; }
    ~DatabaseScratch() { auto ec = std::error_code{}; std::filesystem::remove_all(path, ec); }
    std::filesystem::path path;
};
}
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
        auto const config = merovingian::config::Config{merovingian::config::ServerConfig{}, merovingian::config::ListenersConfig{}, database, merovingian::config::SecurityConfig{}, merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{}};
        WHEN("the production worker load profile bootstraps a snapshot")
        {
            auto worker = merovingian::homeserver::bootstrap_local_database(config, {}, merovingian::database::TableLoadProfile::federation_worker);
            THEN("reads work and writes fail without affecting main's write path")
            {
                REQUIRE(worker.opened);
                REQUIRE(worker.persistent_store.rooms.size() == 1U);
                REQUIRE_FALSE(merovingian::database::store_room(worker.persistent_store, {"!worker:example.org", "@a:example.org"}));
                REQUIRE(merovingian::database::store_room(main.store, {"!main:example.org", "@a:example.org"}));
                auto const reopened = merovingian::database::open_sqlite_persistent_store(path);
                REQUIRE(reopened.ok);
                REQUIRE(reopened.store.rooms.size() == 2U);
            }
        }
    }
}
#if defined(__linux__)
SCENARIO("Landlocked production SQLite worker cannot open main's database for writing", "[database][iso4][iso4_landlock]")
{
    GIVEN("main's initialized SQLite database and the real kernel Landlock API")
    {
        auto const ops = merovingian::platform::LandlockHardeningOps{};
        if (ops.query_abi_version() < 1) { SKIP("kernel has no Landlock support"); }
        auto scratch = DatabaseScratch{};
        auto const path = (scratch.path / "store.db").string();
        auto main = merovingian::database::open_sqlite_persistent_store(path);
        REQUIRE(main.ok);
        REQUIRE(merovingian::database::store_room(main.store, {"!original:example.org", "@a:example.org"}));
        auto database = merovingian::config::DatabaseConfig{};
        database.backend = merovingian::config::DatabaseBackend::sqlite;
        database.sqlite_path = path;
        auto const config = merovingian::config::Config{merovingian::config::ServerConfig{}, merovingian::config::ListenersConfig{}, database, merovingian::config::SecurityConfig{}, merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{}};
        WHEN("a child installs the exact worker filesystem policy before production bootstrap")
        {
            auto const pid = ::fork();
            REQUIRE(pid >= 0);
            if (pid == 0)
            {
                auto const hardened = merovingian::platform::apply_worker_landlock(merovingian::platform::build_worker_landlock_rules(config), false);
                if (!hardened.applied) { ::_exit(10); }
                auto write = merovingian::core::FileDescriptor{::open(path.c_str(), O_RDWR | O_CLOEXEC)};
                if (write.valid()) { ::_exit(11); }
                auto worker = merovingian::homeserver::bootstrap_local_database(config, {}, merovingian::database::TableLoadProfile::federation_worker);
                if (!worker.opened || worker.persistent_store.rooms.size() != 1U) { ::_exit(12); }
                if (merovingian::database::store_room(worker.persistent_store, {"!worker:example.org", "@a:example.org"})) { ::_exit(13); }
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
SCENARIO("SQLite refuses symlinked database paths without changing their targets", "[database][db10]")
{
    GIVEN("a database symlink and a directory symlink")
    {
        auto scratch = DatabaseScratch{};
        auto const target = scratch.path / "target.db";
        REQUIRE(merovingian::database::open_sqlite_persistent_store(target.string()).ok);
        auto const alias = scratch.path / "alias.db";
        std::filesystem::create_symlink(target, alias);
        auto const dir_alias = scratch.path / "alias-dir";
        std::filesystem::create_directory_symlink(scratch.path, dir_alias);
        WHEN("either path is opened")
        {
            THEN("both are refused and the original database remains usable")
            {
                REQUIRE_FALSE(merovingian::database::open_sqlite_persistent_store(alias.string()).ok);
                REQUIRE_FALSE(merovingian::database::open_sqlite_persistent_store((dir_alias / "target.db").string()).ok);
                REQUIRE(merovingian::database::open_sqlite_persistent_store(target.string()).ok);
            }
        }
    }
}
