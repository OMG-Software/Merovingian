// SPDX-License-Identifier: GPL-3.0-or-later

// HTTP-5 (security-audit-report-2026-09-29.md): SIGPIPE was never ignored, so a
// TLS client that completed the handshake and then reset the connection made
// OpenSSL write() to a dead socket and the default disposition killed the
// whole server. `platform::ignore_sigpipe()` is called first thing by every
// executable's main().
//
// The default disposition is process-wide and irreversible in spirit, and the
// integration-test harness ignores SIGPIPE for its whole binary, which is what
// hid the defect. Each scenario therefore runs in a forked child that first
// resets SIGPIPE to SIG_DFL, so it never inherits any harness setting.

#include "merovingian/platform/signal_hardening.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cerrno>
#include <csignal>

#include <sys/wait.h>
#include <unistd.h>

namespace
{

enum class ChildAction
{
    write_without_ignoring,
    write_after_ignoring,
    ignore_twice_then_write,
};

// Runs `action` in a forked child and returns its wait status. The child
// resets SIGPIPE to SIG_DFL, optionally calls ignore_sigpipe(), writes to a
// pipe whose read end is closed, and exits 0 only when the write failed with
// EPIPE. Exit 2: the write unexpectedly succeeded or failed differently.
// Exit 3: ignore_sigpipe() was refused.
[[nodiscard]] auto run_child(ChildAction action) -> int
{
    auto const pid = ::fork();
    REQUIRE(pid >= 0);
    if (pid == 0)
    {
        struct sigaction dfl
        {
        };
        dfl.sa_handler = SIG_DFL;
        ::sigemptyset(&dfl.sa_mask);
        ::sigaction(SIGPIPE, &dfl, nullptr);

        if (action != ChildAction::write_without_ignoring)
        {
            if (!merovingian::platform::ignore_sigpipe().accepted)
            {
                ::_exit(3);
            }
            if (action == ChildAction::ignore_twice_then_write && !merovingian::platform::ignore_sigpipe().accepted)
            {
                ::_exit(3);
            }
        }

        int fds[2] = {-1, -1};
        if (::pipe(fds) != 0)
        {
            ::_exit(4);
        }
        ::close(fds[0]);
        errno = 0;
        auto const written = ::write(fds[1], "x", 1U);
        ::_exit(written < 0 && errno == EPIPE ? 0 : 2);
    }

    auto status = int{};
    REQUIRE(::waitpid(pid, &status, 0) == pid);
    return status;
}

} // namespace

SCENARIO("ignore_sigpipe stops a write to a dead peer from killing the process",
         "[platform][signal][sigpipe][security]")
{
    GIVEN("a process whose SIGPIPE disposition is the default")
    {
        WHEN("it writes to a pipe whose read end is closed and never called ignore_sigpipe")
        {
            auto const status = run_child(ChildAction::write_without_ignoring);

            THEN("the kernel terminates it with SIGPIPE, which proves the scenarios below are meaningful")
            {
                REQUIRE(WIFSIGNALED(status));
                REQUIRE(WTERMSIG(status) == SIGPIPE);
            }
        }

        WHEN("it calls ignore_sigpipe and then writes to a pipe whose read end is closed")
        {
            auto const status = run_child(ChildAction::write_after_ignoring);

            THEN("the process survives and the write fails with EPIPE")
            {
                REQUIRE_FALSE(WIFSIGNALED(status));
                REQUIRE(WIFEXITED(status));
                REQUIRE(WEXITSTATUS(status) == 0);
            }
        }

        WHEN("ignore_sigpipe is called twice")
        {
            auto const status = run_child(ChildAction::ignore_twice_then_write);

            THEN("both calls are accepted and the process still survives the write")
            {
                REQUIRE(WIFEXITED(status));
                REQUIRE(WEXITSTATUS(status) == 0);
            }
        }
    }
}

SCENARIO("ignore_sigpipe reports success as a fail-closed decision", "[platform][signal][sigpipe]")
{
    GIVEN("a process about to start serving")
    {
        WHEN("ignore_sigpipe succeeds")
        {
            // Run in a child so the test binary's own disposition is untouched.
            auto const pid = ::fork();
            REQUIRE(pid >= 0);
            if (pid == 0)
            {
                auto const decision = merovingian::platform::ignore_sigpipe();
                ::_exit(decision.accepted && decision.reason.empty() && decision.fail_closed ? 0 : 1);
            }
            auto status = int{};
            REQUIRE(::waitpid(pid, &status, 0) == pid);

            THEN("the decision is accepted with no failure reason")
            {
                REQUIRE(WIFEXITED(status));
                REQUIRE(WEXITSTATUS(status) == 0);
            }
        }
    }
}
