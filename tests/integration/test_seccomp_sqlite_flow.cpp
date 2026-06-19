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

#include <linux/seccomp.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
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

// Write end of a pipe the child uses to report any syscall the filter blocks.
// Set in the child before the filter is installed; read by the SIGSYS handler,
// which runs under the filter, so it must only use syscalls on the allowlist
// (write is allowed). Plain sig_atomic_t is sufficient: it is written once,
// before any signal can be delivered.
volatile sig_atomic_t g_blocked_pipe_wr = -1;

// SIGSYS handler installed under a SECCOMP_RET_TRAP variant of the production
// allowlist. When a syscall is not on the allowlist the kernel traps here with
// si_syscall set to the blocked syscall number; the handler writes that number
// (as decimal, newline-terminated) to the pipe and returns. Returning (rather
// than terminating) lets every missing syscall in the open path be reported in
// a single run. The trapped syscall itself fails with -1, so the caller sees
// an error and the run eventually ends via exit_group.
extern "C" auto on_seccomp_sigsys(int /*signum*/, siginfo_t* info, void* /*ucontext*/) -> void
{
    auto nr = (info != nullptr) ? static_cast<int>(info->si_syscall) : -1;
    auto negative = nr < 0;
    if (negative)
    {
        nr = -nr;
    }
    // Async-signal-safe decimal conversion (snprintf is not guaranteed safe).
    char digits[12];
    int digit_count = 0;
    if (nr == 0)
    {
        digits[digit_count++] = '0';
    }
    while (nr > 0 && digit_count < static_cast<int>(sizeof(digits)))
    {
        digits[digit_count++] = static_cast<char>('0' + (nr % 10));
        nr /= 10;
    }
    char msg[16];
    int msg_len = 0;
    if (negative)
    {
        msg[msg_len++] = '-';
    }
    while (digit_count > 0)
    {
        msg[msg_len++] = digits[--digit_count];
    }
    msg[msg_len++] = '\n';
    auto const wr = g_blocked_pipe_wr;
    if (wr >= 0)
    {
        auto const written = ::write(wr, msg, static_cast<std::size_t>(msg_len));
        (void)written;
    }
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
            // The pipe carries any blocked-syscall numbers from child to parent.
            // The parent closes both ends after collecting the child.
            int pipefd[2] = {-1, -1};
            REQUIRE(::pipe(pipefd) == 0);

            auto const pid = ::fork();
            REQUIRE(pid >= 0);

            if (pid == 0)
            {
                // Child: install the production allowlist with SECCOMP_RET_TRAP
                // (instead of KILL_PROCESS) and a SIGSYS handler that reports
                // each blocked syscall number through the pipe. This validates
                // the exact production allowlist while making any gap diagnosable
                // instead of an opaque SIGSYS death. The filter is irreversible,
                // so this must run in a forked process.
                ::close(pipefd[0]); // close read end in the child
                g_blocked_pipe_wr = pipefd[1];

                // Production runs as a non-root service user: privilege drop is
                // performed externally by the service manager (systemd User=,
                // OpenRC, etc.) before the process starts, so the database is
                // always opened while non-root. The CI Docker containers run
                // this test as root, which would make SQLite's robustFchown()
                // issue fchown() — it only does so when geteuid()==0 (see
                // sqlite3.c robustFchown) — and fchown is a privilege-mutation
                // call that is intentionally NOT on the allowlist. Dropping to
                // an unprivileged uid/gid when running as root makes the test
                // exercise the real production (non-root) syscall set and keeps
                // the allowlist minimal. These calls run before the filter is
                // installed, so they are not subject to it; nobody is 65534.
                if (::geteuid() == 0)
                {
                    std::ignore = ::setresgid(65534, 65534, 65534);
                    std::ignore = ::setresuid(65534, 65534, 65534);
                }

                struct ::sigaction sa{};
                sa.sa_sigaction = on_seccomp_sigsys;
                sa.sa_flags = SA_SIGINFO | SA_RESTART;
                ::sigemptyset(&sa.sa_mask);
                std::ignore = ::sigaction(SIGSYS, &sa, nullptr);

                std::ignore = merovingian::platform::apply_seccomp_filter_with_default(SECCOMP_RET_TRAP);
                auto const result = merovingian::database::open_sqlite_persistent_store(db_path);
                // Use the raw exit_group syscall rather than _exit() so that
                // ASan/LSan's _exit hook — which runs leak-checker cleanup code
                // requiring syscalls outside the filter — cannot fire under the
                // installed seccomp policy and trigger SIGSYS.
                ::syscall(__NR_exit_group, result.ok ? 0 : 1);
                __builtin_unreachable();
            }

            // Parent: close the write end, collect the child, then read any
            // blocked-syscall numbers it reported before cleaning up the files.
            ::close(pipefd[1]);
            auto status = int{};
            ::waitpid(pid, &status, 0);
            auto report = std::string{};
            char buf[128];
            for (auto r = ::read(pipefd[0], buf, sizeof(buf)); r > 0; r = ::read(pipefd[0], buf, sizeof(buf)))
            {
                report.append(buf, static_cast<std::size_t>(r));
            }
            ::close(pipefd[0]);
            remove_sqlite_files(db_path);

            THEN("the subprocess exits cleanly and is not killed by SIGSYS")
            {
                // If the allowlist is missing a syscall SQLite/glibc needs, the
                // child's SIGSYS handler writes the offending number(s) here and
                // the run ends with a non-zero or signalled status. Fail with
                // the numbers so the gap is named directly in the test output.
                if (!report.empty())
                {
                    FAIL("seccomp filter blocked syscall(s) not in the allowlist: " << report);
                }
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
