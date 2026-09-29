// SPDX-License-Identifier: GPL-3.0-or-later

// ISO-1 (security-audit-report-2026-09-29.md): the federation worker's Landlock
// ruleset and seccomp filter applied to the calling thread only, and the
// logger's writer threads already existed by then, so they escaped both. The
// fix has three parts, each covered here:
//   * the seccomp filter is installed with SECCOMP_FILTER_FLAG_TSYNC, so a
//     thread that already exists is confined too (fork test, real kernel);
//   * no thread is started before hardening, so Landlock (which has no TSYNC on
//     older kernels) covers every thread (fork test, real kernel);
//   * the hardening self-check inspects every task, not just the thread-group
//     leader, because /proc/self/status describes only the leader.
//
// Seccomp and Landlock are irreversible, so every enforcement scenario runs in
// a forked child that reports to the parent through a pipe and its exit
// status. A kernel without seccomp or Landlock makes the scenario SKIP with a
// message; it never passes silently.

#include "merovingian/observability/logger.hpp"
#include "merovingian/platform/hardening_self_check.hpp"
#include "merovingian/platform/landlock_hardening.hpp"
#include "merovingian/platform/runtime_hardening.hpp"
#include "merovingian/platform/seccomp_hardening.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <string_view>

#ifdef __linux__
#include "../support/process_tasks.hpp"
#include "../support/temp_directory.hpp"

#include <cerrno>
#include <cstddef>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <functional>
#include <system_error>
#include <thread>
#include <tuple>
#include <vector>

#include <fcntl.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

using merovingian::platform::parse_task_confinement;

SCENARIO("A task is confined only when it has a seccomp filter and no_new_privs", "[platform][seccomp][iso1]")
{
    GIVEN("the status text of a task with a filter and no_new_privs")
    {
        auto const text =
            std::string_view{"Name:\tx\nNoNewPrivs:\t1\nSeccomp:\t2\nSeccomp_filters:\t1\nSpeculation:\t0\n"};

        WHEN("it is parsed")
        {
            auto const result = parse_task_confinement(text);

            THEN("it is confined")
            {
                REQUIRE(result.parsed);
                REQUIRE(result.seccomp_mode == 2);
                REQUIRE(result.no_new_privs == 1);
                REQUIRE(result.confined());
            }
        }
    }

    GIVEN("status texts that each lack one of the two protections")
    {
        auto const no_filter = std::string_view{"NoNewPrivs:\t1\nSeccomp:\t0\n"};
        auto const strict_mode = std::string_view{"NoNewPrivs:\t1\nSeccomp:\t1\n"};
        auto const no_nnp = std::string_view{"NoNewPrivs:\t0\nSeccomp:\t2\n"};

        WHEN("each is parsed")
        {
            THEN("none is confined")
            {
                REQUIRE_FALSE(parse_task_confinement(no_filter).confined());
                REQUIRE_FALSE(parse_task_confinement(strict_mode).confined());
                REQUIRE_FALSE(parse_task_confinement(no_nnp).confined());
            }
        }
    }

    GIVEN("status texts that are incomplete or malformed")
    {
        auto const missing_nnp = std::string_view{"Seccomp:\t2\n"};
        auto const missing_seccomp = std::string_view{"NoNewPrivs:\t1\n"};
        auto const only_filters_line = std::string_view{"NoNewPrivs:\t1\nSeccomp_filters:\t2\n"};
        auto const not_numeric = std::string_view{"NoNewPrivs:\t1\nSeccomp:\tx\n"};
        auto const empty = std::string_view{};

        WHEN("each is parsed")
        {
            THEN("none is confined, so an unreadable task fails closed")
            {
                REQUIRE_FALSE(parse_task_confinement(missing_nnp).confined());
                REQUIRE_FALSE(parse_task_confinement(missing_seccomp).confined());
                REQUIRE_FALSE(parse_task_confinement(only_filters_line).confined());
                REQUIRE_FALSE(parse_task_confinement(not_numeric).confined());
                REQUIRE_FALSE(parse_task_confinement(empty).parsed);
            }
        }
    }
}

#ifdef __linux__
namespace
{

struct ChildOutcome final
{
    std::string report{};
    int status{0};
};

// Runs `body` in a forked child. The body writes its verdict to the report fd
// ("OK...", "SKIP:<why>" or "FAIL:<why>") and returns; the child then _exit(0)s.
[[nodiscard]] auto run_in_child(std::function<void(int report_fd)> const& body) -> ChildOutcome
{
    int fds[2] = {-1, -1};
    REQUIRE(::pipe(fds) == 0);
    auto const pid = ::fork();
    REQUIRE(pid >= 0);
    if (pid == 0)
    {
        ::close(fds[0]);
        body(fds[1]);
        ::_exit(0);
    }
    ::close(fds[1]);
    auto outcome = ChildOutcome{};
    char buf[512];
    for (auto n = ::read(fds[0], buf, sizeof(buf)); n > 0; n = ::read(fds[0], buf, sizeof(buf)))
    {
        outcome.report.append(buf, static_cast<std::size_t>(n));
    }
    ::close(fds[0]);
    REQUIRE(::waitpid(pid, &outcome.status, 0) == pid);
    return outcome;
}

auto report(int fd, std::string const& text) -> void
{
    std::ignore = ::write(fd, text.data(), text.size());
}

// prctl(PR_GET_SECCOMP) fails with EINVAL when the kernel has no seccomp.
[[nodiscard]] auto kernel_has_seccomp() -> bool
{
    return ::prctl(PR_GET_SECCOMP) >= 0 || errno != EINVAL;
}

[[nodiscard]] auto hardening_failure(merovingian::platform::HardeningPlanDecision const& decision) -> std::string
{
    return (kernel_has_seccomp() ? std::string{"FAIL:"} : std::string{"SKIP:the kernel has no seccomp support: "}) +
           decision.reason;
}

// Marks the scenario skipped (never passed) when the child reported SKIP.
auto skip_if_reported(std::string const& report_text) -> void
{
    if (report_text.starts_with("SKIP:"))
    {
        SKIP("cannot enforce on this kernel: " << report_text.substr(5));
    }
}

} // namespace

SCENARIO("Worker seccomp hardening confines a thread that existed before it was applied",
         "[platform][seccomp][iso1][tsync][worker_hardening][linux]")
{
    GIVEN("a process that has already logged and already has a second thread, as the logger's writers once were")
    {
        WHEN("the worker hardening sequence is applied and the earlier thread then tries to execve")
        {
            auto const outcome = run_in_child([](int report_fd) {
                merovingian::observability::SingleLog::instance().info("iso1-test", "logged before hardening");

                int go[2] = {-1, -1};
                if (::pipe(go) != 0)
                {
                    report(report_fd, "FAIL:pipe");
                    return;
                }
                auto earlier_thread = std::thread{[&go] {
                    char byte = 0;
                    std::ignore = ::read(go[0], &byte, 1U);
                    char arg0[] = "true";                 // NOLINT(*-avoid-c-arrays)
                    char* const argv[] = {arg0, nullptr}; // NOLINT(*-avoid-c-arrays)
                    char* const envp[] = {nullptr};       // NOLINT(*-avoid-c-arrays)
                    ::execve("/bin/true", argv, envp);
                    // Reached only if execve returned: it was not killed by the filter.
                    ::_exit(3);
                }};

                auto const hardening = merovingian::platform::apply_worker_hardening();
                if (!hardening.accepted)
                {
                    report(report_fd, hardening_failure(hardening));
                    ::_exit(0);
                }

                auto const probe = merovingian::platform::probe_seccomp_status();
                report(report_fd, "OK tasks=" + std::to_string(probe.tasks_checked) +
                                      " unconfined=" + std::to_string(probe.unconfined_tasks) +
                                      " active=" + (probe.seccomp_active ? "1" : "0"));

                std::ignore = ::write(go[1], "g", 1U);
                earlier_thread.join();
            });
            skip_if_reported(outcome.report);
            INFO("child report: " << outcome.report);

            THEN("every task reports Seccomp: 2 and NoNewPrivs: 1")
            {
                REQUIRE(outcome.report.starts_with("OK tasks="));
                REQUIRE(outcome.report.starts_with("OK tasks=2 "));
                REQUIRE(outcome.report.find("unconfined=0 ") != std::string::npos);
                REQUIRE(outcome.report.find("active=1") != std::string::npos);
            }

            THEN("the earlier thread is killed by the filter instead of replacing the process")
            {
                REQUIRE(WIFSIGNALED(outcome.status));
                REQUIRE(WTERMSIG(outcome.status) == SIGSYS);
            }
        }
    }
}

SCENARIO("Logging before hardening starts no thread, so Landlock and seccomp cover every logger thread",
         "[platform][seccomp][landlock][iso1][worker_hardening][linux]")
{
    GIVEN("a directory the worker may read and a master key file outside it")
    {
        auto const base = merovingian::tests::temporary_directory() / "merovingian-iso1-hardening-test";
        auto const allowed_dir = base / "allowed";
        auto const secret_dir = base / "secret";
        std::filesystem::create_directories(allowed_dir);
        std::filesystem::create_directories(secret_dir);
        auto const master_key = secret_dir / "master.key";
        std::ofstream{master_key} << "not a real key";

        WHEN("a process logs, applies Landlock and worker seccomp, and only then starts the logger's writers")
        {
            auto const outcome = run_in_child([&](int report_fd) {
                namespace platform = merovingian::platform;
                auto logger = merovingian::observability::SingleLog{};
                logger.set_console_log_level(merovingian::observability::LogLevel::off);
                logger.set_file_log_level(merovingian::observability::LogLevel::off);
                logger.info("iso1-test", "logged before hardening");

                if (auto const tasks = merovingian::tests::count_process_tasks(); tasks != 1U)
                {
                    report(report_fd,
                           "FAIL:logging created " + std::to_string(tasks - 1U) + " thread(s) before hardening");
                    return;
                }

                // /proc/self is granted read-only only so this child can inspect its own
                // tasks after Landlock is applied; the real worker grants no /proc path.
                auto const rules = std::vector<platform::LandlockPathRule>{
                    {.path = allowed_dir.string(), .access = platform::LandlockAccess::read_only, .required = true},
                    {.path = "/proc/self",         .access = platform::LandlockAccess::read_only, .required = true},
                };
                auto const landlock = platform::apply_worker_landlock(rules, /*allow_without_landlock=*/false);
                if (!landlock.accepted)
                {
                    auto const abi = platform::LandlockHardeningOps{}.query_abi_version();
                    report(report_fd, (abi < 1 ? std::string{"SKIP:no Landlock: "} : std::string{"FAIL:landlock: "}) +
                                          landlock.reason);
                    return;
                }
                auto const hardening = platform::apply_worker_hardening();
                if (!hardening.accepted)
                {
                    report(report_fd, hardening_failure(hardening));
                    return;
                }

                if (!logger.start_writers())
                {
                    report(report_fd, "FAIL:start_writers");
                    return;
                }
                logger.info("iso1-test", "logged after hardening");

                auto const probe = platform::probe_seccomp_status();
                auto const open_secret = [&master_key] {
                    errno = 0;
                    auto const fd = ::open(master_key.c_str(), O_RDONLY | O_CLOEXEC); // NOLINT(*-vararg)
                    auto const err = errno;
                    if (fd >= 0)
                    {
                        ::close(fd);
                    }
                    return fd < 0 ? err : 0;
                };
                auto thread_errno = int{-1};
                auto opener = std::thread{[&] {
                    thread_errno = open_secret();
                }};
                opener.join();

                report(report_fd, "OK tasks=" + std::to_string(probe.tasks_checked) +
                                      " unconfined=" + std::to_string(probe.unconfined_tasks) + " main_open=" +
                                      std::to_string(open_secret()) + " thread_open=" + std::to_string(thread_errno));
            });
            std::error_code ec;
            std::filesystem::remove_all(base, ec);
            skip_if_reported(outcome.report);
            INFO("child report: " << outcome.report);

            THEN("the writers exist, every task is confined, and none can open the master key")
            {
                REQUIRE(WIFEXITED(outcome.status));
                REQUIRE(WEXITSTATUS(outcome.status) == 0);
                // Leader plus the logger's two writers.
                REQUIRE(outcome.report.starts_with("OK tasks=3 unconfined=0 "));
                REQUIRE(outcome.report.find("main_open=" + std::to_string(EACCES)) != std::string::npos);
                REQUIRE(outcome.report.find("thread_open=" + std::to_string(EACCES)) != std::string::npos);
            }
        }
    }
}
#endif // __linux__

SCENARIO("The seccomp probe walks every task", "[platform][seccomp][iso1]")
{
    GIVEN("the test process")
    {
        WHEN("the seccomp status is probed")
        {
            auto const probe = merovingian::platform::probe_seccomp_status();

            THEN("the counters are consistent with the verdict")
            {
#ifdef __linux__
                REQUIRE(probe.probed);
                REQUIRE(probe.tasks_checked >= 1U);
                REQUIRE(probe.unconfined_tasks <= probe.tasks_checked);
                REQUIRE(probe.seccomp_active == (probe.unconfined_tasks == 0U));
#else
                REQUIRE_FALSE(probe.probed);
                REQUIRE_FALSE(probe.seccomp_active);
#endif
            }
        }
    }
}
