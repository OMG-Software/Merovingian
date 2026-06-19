// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/platform/hardening_self_check.hpp"
#include "merovingian/platform/seccomp_hardening.hpp"

#include <catch2/catch_test_macros.hpp>

#ifdef __linux__
#include <cstdint>

#include <linux/audit.h>
#include <linux/seccomp.h>
#include <sys/syscall.h>
#include <unistd.h>
#endif

SCENARIO("seccomp hardening check maps probe results to the correct status", "[platform][hardening][seccomp]")
{
    GIVEN("a probe result indicating the filter is active")
    {
        auto const result = merovingian::platform::SeccompProbeResult{.probed = true, .seccomp_active = true};

        WHEN("the check is derived from the probe")
        {
            auto const check = merovingian::platform::seccomp_check_from_probe(result);

            THEN("the check is enabled")
            {
                REQUIRE(check.status == merovingian::platform::HardeningStatus::enabled);
                REQUIRE(check.note.empty());
            }
        }
    }

    GIVEN("a probe result where the probe ran but no filter is active")
    {
        auto const result = merovingian::platform::SeccompProbeResult{.probed = true, .seccomp_active = false};

        WHEN("the check is derived from the probe")
        {
            auto const check = merovingian::platform::seccomp_check_from_probe(result);

            THEN("the check is unknown with a non-empty note")
            {
                REQUIRE(check.status == merovingian::platform::HardeningStatus::unknown);
                REQUIRE_FALSE(check.note.empty());
            }
        }
    }

    GIVEN("a probe result where the probe could not run")
    {
        auto const result = merovingian::platform::SeccompProbeResult{.probed = false, .seccomp_active = false};

        WHEN("the check is derived from the probe")
        {
            auto const check = merovingian::platform::seccomp_check_from_probe(result);

            THEN("the check is unknown")
            {
                REQUIRE(check.status == merovingian::platform::HardeningStatus::unknown);
            }
        }
    }

    GIVEN("any probe result")
    {
        auto const active = merovingian::platform::SeccompProbeResult{.probed = true, .seccomp_active = true};
        auto const inactive = merovingian::platform::SeccompProbeResult{.probed = true, .seccomp_active = false};
        auto const unprobed = merovingian::platform::SeccompProbeResult{.probed = false, .seccomp_active = false};

        WHEN("checks are derived from each result")
        {
            auto const check_active = merovingian::platform::seccomp_check_from_probe(active);
            auto const check_inactive = merovingian::platform::seccomp_check_from_probe(inactive);
            auto const check_unprobed = merovingian::platform::seccomp_check_from_probe(unprobed);

            THEN("the check is never alpha_exception or disabled")
            {
                auto constexpr alpha_exception = merovingian::platform::HardeningStatus::alpha_exception;
                auto constexpr disabled = merovingian::platform::HardeningStatus::disabled;
                REQUIRE(check_active.status != alpha_exception);
                REQUIRE(check_inactive.status != alpha_exception);
                REQUIRE(check_unprobed.status != alpha_exception);
                REQUIRE(check_active.status != disabled);
                REQUIRE(check_inactive.status != disabled);
                REQUIRE(check_unprobed.status != disabled);
            }
        }
    }
}

#ifdef __linux__
SCENARIO("seccomp probe reads /proc/self/status successfully on Linux", "[platform][hardening][seccomp][linux]")
{
    GIVEN("a Linux process running the test binary")
    {
        WHEN("the seccomp status is probed")
        {
            auto const result = merovingian::platform::probe_seccomp_status();

            THEN("the probe succeeds and returns a definitive seccomp_active value")
            {
                // probed == true means /proc/self/status was read successfully and
                // the Seccomp: field was parsed. seccomp_active reflects the actual
                // runtime environment — true in Docker containers (Docker's default
                // seccomp profile is active), false on bare hosts without a filter.
                // We do not apply apply_seccomp_filter() here because that would
                // permanently alter the test process's syscall table.
                REQUIRE(result.probed);
                // seccomp_active is environment-dependent; no assertion on its value.
            }
        }
    }
}

SCENARIO("seccomp filter allows SQLite journal ops and blocks privilege-escalation syscalls",
         "[platform][hardening][seccomp][linux]")
{
    GIVEN("the seccomp allowlist constants")
    {
        WHEN("the default action is queried")
        {
            auto const action = merovingian::platform::seccomp_default_action();

            THEN("it is SECCOMP_RET_KILL_PROCESS (fail-closed)")
            {
                REQUIRE(action == static_cast<std::uint32_t>(SECCOMP_RET_KILL_PROCESS));
            }
        }

        WHEN("common I/O and directory-creation syscalls are checked")
        {
            THEN("read, write, openat, and mkdirat are allowed")
            {
                REQUIRE(merovingian::platform::seccomp_is_syscall_allowed(__NR_read));
                REQUIRE(merovingian::platform::seccomp_is_syscall_allowed(__NR_write));
                REQUIRE(merovingian::platform::seccomp_is_syscall_allowed(__NR_openat));
                REQUIRE(merovingian::platform::seccomp_is_syscall_allowed(__NR_mkdirat));
            }
        }

        WHEN("SQLite journal and WAL syscalls are checked")
        {
            THEN("ftruncate, unlink, unlinkat, rename, renameat, statfs and fstatfs are allowed")
            {
                // SQLite DELETE journal mode calls unlinkat to remove the journal
                // on commit, ftruncate during rollback and WAL checkpoint, and
                // rename/renameat in some commit paths. fstatfs/statfs is used
                // early in WAL-mode open to probe device sector size.
                REQUIRE(merovingian::platform::seccomp_is_syscall_allowed(__NR_ftruncate));
                REQUIRE(merovingian::platform::seccomp_is_syscall_allowed(__NR_unlink));
                REQUIRE(merovingian::platform::seccomp_is_syscall_allowed(__NR_unlinkat));
                REQUIRE(merovingian::platform::seccomp_is_syscall_allowed(__NR_rename));
                REQUIRE(merovingian::platform::seccomp_is_syscall_allowed(__NR_renameat));
                REQUIRE(merovingian::platform::seccomp_is_syscall_allowed(__NR_fstatfs));
                REQUIRE(merovingian::platform::seccomp_is_syscall_allowed(__NR_statfs));
            }
        }

        WHEN("privilege-modification filesystem syscalls are checked")
        {
            THEN("chmod, fchmod, fchmodat, umask, mkdir, and truncate remain blocked")
            {
                // Permission bits, ownership, and umask changes are not required
                // after startup. truncate (path-based) is blocked; only the fd-based
                // ftruncate (needed by SQLite) is permitted.
                REQUIRE_FALSE(merovingian::platform::seccomp_is_syscall_allowed(__NR_chmod));
                REQUIRE_FALSE(merovingian::platform::seccomp_is_syscall_allowed(__NR_fchmod));
                REQUIRE_FALSE(merovingian::platform::seccomp_is_syscall_allowed(__NR_fchmodat));
                REQUIRE_FALSE(merovingian::platform::seccomp_is_syscall_allowed(__NR_umask));
                REQUIRE_FALSE(merovingian::platform::seccomp_is_syscall_allowed(__NR_mkdir));
                REQUIRE_FALSE(merovingian::platform::seccomp_is_syscall_allowed(__NR_truncate));
            }
        }

        WHEN("the expected architecture is queried")
        {
            auto const expected = merovingian::platform::seccomp_expected_architecture();

            THEN("x86_64 and aarch64 builds have an architecture constant; unsupported builds fail closed")
            {
#if defined(__x86_64__)
                REQUIRE(expected.has_value());
                REQUIRE(*expected == static_cast<std::uint32_t>(AUDIT_ARCH_X86_64));
#elif defined(__aarch64__)
                REQUIRE(expected.has_value());
                REQUIRE(*expected == static_cast<std::uint32_t>(AUDIT_ARCH_AARCH64));
#else
                REQUIRE_FALSE(expected.has_value());
#endif
            }
        }
    }
}
#endif // __linux__
