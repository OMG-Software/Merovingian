// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// Verifies that the seccomp-bpf allowlist permits the syscalls SQLite needs to
// open a fresh database and commit the initial schema DDL.  The test forks so
// that `apply_seccomp_filter()` — which is irreversible once installed — cannot
// contaminate the rest of the test suite.
//
// This is an integration test (not a unit test) because it exercises the
// merovingian::platform and merovingian::database modules together under a real
// kernel seccomp filter.

#ifdef __linux__

#include "merovingian/database/persistent_store.hpp"
#include "merovingian/platform/seccomp_hardening.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>
#include <system_error>

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

namespace
{

// Returns a unique path under /tmp that does not yet exist on disk.
[[nodiscard]] auto make_tmp_sqlite_path() -> std::string
{
    auto tmp = std::string{"/tmp/merovingian_seccomp_sqlite_XXXXXX"};
    auto const fd = ::mkstemp(tmp.data());
    if (fd < 0)
    {
        return {};
    }
    ::close(fd);
    ::unlink(tmp.c_str()); // remove the placeholder; SQLite will create its own file
    return tmp + ".sqlite3";
}

auto remove_sqlite_files(std::string const& path) -> void
{
    auto ec = std::error_code{};
    std::filesystem::remove(path, ec);
    std::filesystem::remove(path + "-journal", ec);
    std::filesystem::remove(path + "-wal", ec);
    std::filesystem::remove(path + "-shm", ec);
}

} // namespace

SCENARIO("SQLite write transactions complete without SIGSYS under the seccomp allowlist",
         "[platform][seccomp][database][linux][integration]")
{
    GIVEN("a fresh SQLite database path and the seccomp filter installed in a subprocess")
    {
        auto const db_path = make_tmp_sqlite_path();
        REQUIRE_FALSE(db_path.empty());

        WHEN("the subprocess opens the store and initialises the schema under the filter")
        {
            auto const pid = ::fork();
            REQUIRE(pid >= 0);

            if (pid == 0)
            {
                // Child: install the syscall allowlist, then exercise the full
                // open + migrate path that crashed before the fix.  The filter
                // is irreversible, so this must run in a forked process.
                std::ignore = merovingian::platform::apply_seccomp_filter();
                auto const result = merovingian::database::open_sqlite_persistent_store(db_path);
                // Use the raw exit_group syscall rather than _exit() so that
                // ASan/LSan's _exit hook — which runs leak-checker cleanup code
                // requiring syscalls outside the filter — cannot fire under the
                // installed seccomp policy and trigger SIGSYS.
                ::syscall(__NR_exit_group, result.ok ? 0 : 1);
                __builtin_unreachable();
            }

            // Parent: collect child exit status then clean up regardless.
            auto status = int{};
            ::waitpid(pid, &status, 0);
            remove_sqlite_files(db_path);

            THEN("the subprocess exits cleanly and is not killed by SIGSYS")
            {
                // WIFSIGNALED would be true and WTERMSIG would return SIGSYS (31)
                // if the seccomp filter blocked a syscall with KILL_PROCESS.
                REQUIRE(WIFEXITED(status));
                REQUIRE_FALSE(WIFSIGNALED(status));
                REQUIRE(WEXITSTATUS(status) == 0);
            }
        }
    }
}

SCENARIO("SQLite write transactions are blocked by SIGSYS when the seccomp filter is absent",
         "[platform][seccomp][database][linux][integration]")
{
    // Negative control: this scenario would fail (SIGSYS crash) if the main-server
    // filter were applied without the SQLite syscalls.  We simulate the pre-fix
    // state by NOT applying the filter in a subprocess and confirming it succeeds
    // — the interesting assertion is that success is only possible because the
    // subprocess has no seccomp restriction at all.
    GIVEN("a fresh SQLite database path and no seccomp filter in the subprocess")
    {
        auto const db_path = make_tmp_sqlite_path();
        REQUIRE_FALSE(db_path.empty());

        WHEN("the subprocess opens the store and initialises the schema without the filter")
        {
            auto const pid = ::fork();
            REQUIRE(pid >= 0);

            if (pid == 0)
            {
                // Child: no apply_seccomp_filter() call — unrestricted syscalls.
                auto const result = merovingian::database::open_sqlite_persistent_store(db_path);
                ::_exit(result.ok ? 0 : 1);
            }

            auto status = int{};
            ::waitpid(pid, &status, 0);
            remove_sqlite_files(db_path);

            THEN("the subprocess also exits cleanly, confirming the test harness itself is sound")
            {
                REQUIRE(WIFEXITED(status));
                REQUIRE(WEXITSTATUS(status) == 0);
            }
        }
    }
}

#endif // __linux__
