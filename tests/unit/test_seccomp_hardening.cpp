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

            THEN("the check is never disabled")
            {
                auto constexpr disabled = merovingian::platform::HardeningStatus::disabled;
                REQUIRE(check_active.status != disabled);
                REQUIRE(check_inactive.status != disabled);
                REQUIRE(check_unprobed.status != disabled);
            }
        }
    }
}

#ifndef __linux__
SCENARIO("seccomp probe reports not-probed on non-Linux platforms", "[platform][hardening][seccomp][bsd][portable]")
{
    GIVEN("a non-Linux platform with no seccomp-bpf support")
    {
        WHEN("the seccomp status is probed")
        {
            auto const result = merovingian::platform::probe_seccomp_status();

            THEN("the probe reports not-probed, not an error and not active")
            {
                // /proc/self/status does not exist on BSD or other non-Linux
                // systems. probe_seccomp_status must gracefully return
                // probed=false rather than crashing, and seccomp_active must
                // be false because seccomp-bpf only exists on Linux.
                REQUIRE_FALSE(result.probed);
                REQUIRE_FALSE(result.seccomp_active);
            }
        }

        WHEN("the probe result is mapped to a HardeningCheck")
        {
            auto const result = merovingian::platform::probe_seccomp_status();
            auto const check = merovingian::platform::seccomp_check_from_probe(result);

            THEN("the check is unknown — never disabled")
            {
                // On BSD and other non-Linux targets seccomp maps to `unknown`;
                // seccomp-bpf simply does not exist on this OS and unknown is the
                // correct signal. There is no alpha-exception status.
                REQUIRE(check.status == merovingian::platform::HardeningStatus::unknown);
                REQUIRE(check.status != merovingian::platform::HardeningStatus::disabled);
                REQUIRE_FALSE(check.note.empty());
            }
        }
    }
}
#endif // !__linux__

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
            THEN("ftruncate, unlink, unlinkat, rename, renameat, statfs, fstatfs, and fallocate are allowed")
            {
                // SQLite DELETE journal mode calls unlinkat to remove the journal
                // on commit, ftruncate during rollback and WAL checkpoint, and
                // rename/renameat in some commit paths. fstatfs/statfs is used
                // early in WAL-mode open to probe device sector size. fallocate
                // is issued by glibc's posix_fallocate on filesystems that support it.
                REQUIRE(merovingian::platform::seccomp_is_syscall_allowed(__NR_ftruncate));
                REQUIRE(merovingian::platform::seccomp_is_syscall_allowed(__NR_unlink));
                REQUIRE(merovingian::platform::seccomp_is_syscall_allowed(__NR_unlinkat));
                REQUIRE(merovingian::platform::seccomp_is_syscall_allowed(__NR_rename));
                REQUIRE(merovingian::platform::seccomp_is_syscall_allowed(__NR_renameat));
                REQUIRE(merovingian::platform::seccomp_is_syscall_allowed(__NR_fstatfs));
                REQUIRE(merovingian::platform::seccomp_is_syscall_allowed(__NR_statfs));
#ifdef __NR_fallocate
                REQUIRE(merovingian::platform::seccomp_is_syscall_allowed(__NR_fallocate));
#endif
            }
        }

        WHEN("glibc per-CPU and memory-barrier syscalls are checked")
        {
            THEN("rseq, membarrier, and getcpu are allowed")
            {
                // glibc 2.35+ registers a per-thread rseq area after fork() and
                // uses rseq in the malloc per-CPU cache on 2.36+. membarrier is
                // used in the malloc fast path on SMP systems. getcpu feeds the
                // per-CPU TLS cache. All three are blocked by default in a tight
                // filter and must be explicitly allowed.
#ifdef __NR_rseq
                REQUIRE(merovingian::platform::seccomp_is_syscall_allowed(__NR_rseq));
#endif
#ifdef __NR_membarrier
                REQUIRE(merovingian::platform::seccomp_is_syscall_allowed(__NR_membarrier));
#endif
#ifdef __NR_getcpu
                REQUIRE(merovingian::platform::seccomp_is_syscall_allowed(__NR_getcpu));
#endif
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

        WHEN("glibc 2.35+ per-thread syscalls are checked by numeric value regardless of build-time kernel headers")
        {
            THEN("rseq, membarrier, getcpu, and futex_waitv are always present on x86_64 and aarch64")
            {
                // glibc 2.35+ registers a per-thread rseq area after fork() and uses rseq
                // inside the malloc per-CPU cache (2.36+). membarrier is issued in the malloc
                // fast path on SMP systems. getcpu feeds the per-CPU TLS cache.
                // futex_waitv (Linux 5.16) is used by newer condition-variable implementations.
                // Builds against older kernel headers (e.g. Ubuntu 18.04, Linux 4.15) will not
                // define __NR_rseq, __NR_membarrier, __NR_getcpu, or __NR_futex_waitv, so the
                // filter must include them via unconditional numeric fallbacks — exactly as was
                // done for clone3 (435), close_range (436), and faccessat2 (439) in v0.10.6.
                // Without these, the first pthread_create after seccomp installation kills the
                // process via SECCOMP_RET_KILL_PROCESS because glibc's thread init calls rseq.
#if defined(__x86_64__)
                REQUIRE(merovingian::platform::seccomp_is_syscall_allowed(334)); // rseq
                REQUIRE(merovingian::platform::seccomp_is_syscall_allowed(324)); // membarrier
                REQUIRE(merovingian::platform::seccomp_is_syscall_allowed(309)); // getcpu
                REQUIRE(merovingian::platform::seccomp_is_syscall_allowed(449)); // futex_waitv
#elif defined(__aarch64__)
                REQUIRE(merovingian::platform::seccomp_is_syscall_allowed(293)); // rseq
                REQUIRE(merovingian::platform::seccomp_is_syscall_allowed(283)); // membarrier
                REQUIRE(merovingian::platform::seccomp_is_syscall_allowed(168)); // getcpu
                REQUIRE(merovingian::platform::seccomp_is_syscall_allowed(449)); // futex_waitv
#endif
            }
        }

        WHEN("modern Linux syscalls needed by glibc 2.34+ on Fedora are checked")
        {
            THEN("clone3, close_range, and faccessat2 are always allowed on x86_64 and aarch64")
            {
                // glibc 2.34+ uses clone3 (435) for pthread_create and posix_spawn.
                // glibc 2.34+ posix_spawn uses close_range (436) in the child to close
                // inherited file descriptors before exec; the child inherits this filter.
                // glibc 2.33+ uses faccessat2 (439) for faccessat() with AT_SYMLINK_NOFOLLOW
                // on kernels >= 5.8. These must always be present regardless of what
                // __NR_* macros the build-time kernel headers define — binaries built on
                // WSL2 / Ubuntu 20.04 (kernel headers 5.4) would otherwise omit them,
                // causing SIGSYS crashes on modern Fedora/Ubuntu hosts at the first
                // pthread_create or posix_spawn call after seccomp is applied.
#if defined(__x86_64__) || defined(__aarch64__)
                REQUIRE(merovingian::platform::seccomp_is_syscall_allowed(435)); // clone3
                REQUIRE(merovingian::platform::seccomp_is_syscall_allowed(436)); // close_range
                REQUIRE(merovingian::platform::seccomp_is_syscall_allowed(439)); // faccessat2
#endif
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

SCENARIO("seccomp filter allows ThreadSanitizer worker startup syscalls", "[platform][hardening][seccomp][linux]")
{
    GIVEN("the seccomp allowlist constants")
    {
        WHEN("sanitizer runtime syscalls are checked")
        {
            THEN("personality is allowed")
            {
                // ThreadSanitizer calls personality(ADDR_NO_RANDOMIZE) in the
                // federation worker after exec to disable ASLR for deterministic
                // shadow-memory layout. The worker inherits the server's seccomp
                // filter, so blocking personality kills the child with SIGSYS.
#ifdef __NR_personality
                REQUIRE(merovingian::platform::seccomp_is_syscall_allowed(__NR_personality));
#endif
            }
        }
    }
}
#endif // __linux__
