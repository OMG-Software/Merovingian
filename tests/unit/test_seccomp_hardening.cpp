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

// #428: personality() is allowed in the seccomp allowlist only for
// ThreadSanitizer builds (which call personality(ADDR_NO_RANDOMIZE) during
// worker startup after exec); production builds must not carry it, since it
// would let an attacker with arbitrary code execution disable ASLR. Mirrors
// the sanitizer-detection pattern in media/thumbnail_worker_main.cpp. Scoped
// to __linux__ (like the scenarios that use it below): seccomp is Linux-only,
// so on other platforms this constant is unused and -Werror would reject it.
#if defined(__has_feature)
#if __has_feature(thread_sanitizer)
constexpr bool tsan_build = true;
#else
constexpr bool tsan_build = false;
#endif
#elif defined(__SANITIZE_THREAD__)
constexpr bool tsan_build = true;
#else
constexpr bool tsan_build = false;
#endif
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
            THEN("personality is allowed only in ThreadSanitizer builds")
            {
                // ThreadSanitizer calls personality(ADDR_NO_RANDOMIZE) in the
                // federation worker after exec to disable ASLR for deterministic
                // shadow-memory layout. The worker inherits the server's seccomp
                // filter, so blocking personality kills the child with SIGSYS.
                // Production (non-TSan) builds must NOT carry this syscall (#428):
                // it would let an attacker with arbitrary code execution disable
                // ASLR, weakening a core exploit mitigation.
#ifdef __NR_personality
                if constexpr (tsan_build)
                {
                    REQUIRE(merovingian::platform::seccomp_is_syscall_allowed(__NR_personality));
                }
                else
                {
                    REQUIRE_FALSE(merovingian::platform::seccomp_is_syscall_allowed(__NR_personality));
                }
#endif
            }
        }
    }
}

SCENARIO("worker seccomp filter denies exec/spawn syscalls but allows the worker runtime set",
         "[platform][hardening][seccomp][worker][linux]")
{
    GIVEN("the worker seccomp allowlist (issue #319)")
    {
        WHEN("the default action is queried")
        {
            THEN("it is SECCOMP_RET_KILL_PROCESS (fail-closed, same as the main filter)")
            {
                REQUIRE(merovingian::platform::worker_seccomp_default_action() ==
                        static_cast<std::uint32_t>(SECCOMP_RET_KILL_PROCESS));
            }
        }
        WHEN("spawn syscalls are checked")
        {
            THEN("execve and execveat are denied — the worker never spawns or execs")
            {
                REQUIRE_FALSE(merovingian::platform::worker_seccomp_is_syscall_allowed(__NR_execve));
#ifdef __NR_execveat
                REQUIRE_FALSE(merovingian::platform::worker_seccomp_is_syscall_allowed(__NR_execveat));
#endif
            }
        }
        WHEN("the worker runtime syscall set is checked")
        {
            THEN("I/O, threads, network, mlock, getrandom, and SQLite journal ops are allowed")
            {
                REQUIRE(merovingian::platform::worker_seccomp_is_syscall_allowed(__NR_read));
                REQUIRE(merovingian::platform::worker_seccomp_is_syscall_allowed(__NR_write));
                REQUIRE(merovingian::platform::worker_seccomp_is_syscall_allowed(__NR_openat));
                REQUIRE(merovingian::platform::worker_seccomp_is_syscall_allowed(__NR_close));
                REQUIRE(merovingian::platform::worker_seccomp_is_syscall_allowed(__NR_socket));
                REQUIRE(merovingian::platform::worker_seccomp_is_syscall_allowed(__NR_connect));
                REQUIRE(merovingian::platform::worker_seccomp_is_syscall_allowed(__NR_clone));
                REQUIRE(merovingian::platform::worker_seccomp_is_syscall_allowed(__NR_futex));
                REQUIRE(merovingian::platform::worker_seccomp_is_syscall_allowed(__NR_mlock));
                REQUIRE(merovingian::platform::worker_seccomp_is_syscall_allowed(__NR_getrandom));
                REQUIRE(merovingian::platform::worker_seccomp_is_syscall_allowed(__NR_unlink));
                REQUIRE(merovingian::platform::worker_seccomp_is_syscall_allowed(__NR_ftruncate));
            }
        }
        WHEN("the glibc per-thread syscalls are checked by numeric value")
        {
            THEN("rseq, membarrier, getcpu, futex_waitv, clone3, close_range, and faccessat2 are present")
            {
#if defined(__x86_64__)
                REQUIRE(merovingian::platform::worker_seccomp_is_syscall_allowed(334)); // rseq
                REQUIRE(merovingian::platform::worker_seccomp_is_syscall_allowed(324)); // membarrier
                REQUIRE(merovingian::platform::worker_seccomp_is_syscall_allowed(309)); // getcpu
                REQUIRE(merovingian::platform::worker_seccomp_is_syscall_allowed(449)); // futex_waitv
                REQUIRE(merovingian::platform::worker_seccomp_is_syscall_allowed(435)); // clone3
                REQUIRE(merovingian::platform::worker_seccomp_is_syscall_allowed(436)); // close_range
                REQUIRE(merovingian::platform::worker_seccomp_is_syscall_allowed(439)); // faccessat2
#elif defined(__aarch64__)
                REQUIRE(merovingian::platform::worker_seccomp_is_syscall_allowed(293)); // rseq
                REQUIRE(merovingian::platform::worker_seccomp_is_syscall_allowed(283)); // membarrier
                REQUIRE(merovingian::platform::worker_seccomp_is_syscall_allowed(168)); // getcpu
                REQUIRE(merovingian::platform::worker_seccomp_is_syscall_allowed(449)); // futex_waitv
                REQUIRE(merovingian::platform::worker_seccomp_is_syscall_allowed(435)); // clone3
                REQUIRE(merovingian::platform::worker_seccomp_is_syscall_allowed(436)); // close_range
                REQUIRE(merovingian::platform::worker_seccomp_is_syscall_allowed(439)); // faccessat2
#endif
            }
        }
        WHEN("ThreadSanitizer's personality syscall is checked")
        {
            THEN("personality is allowed in the worker filter too, only for ThreadSanitizer builds")
            {
                // #428: production (non-TSan) builds must not carry this
                // syscall in the worker filter either.
#ifdef __NR_personality
                if constexpr (tsan_build)
                {
                    REQUIRE(merovingian::platform::worker_seccomp_is_syscall_allowed(__NR_personality));
                }
                else
                {
                    REQUIRE_FALSE(merovingian::platform::worker_seccomp_is_syscall_allowed(__NR_personality));
                }
#endif
            }
        }
        WHEN("the worker allowlist is compared against the main allowlist")
        {
            THEN("the worker allowlist is a strict subset — execve/execveat are in main but not worker")
            {
                // This guards against drift: every syscall the worker allows the
                // main process must also allow (worker is a subset), and the two
                // spawn syscalls must be present in main but absent in worker.
                REQUIRE(merovingian::platform::seccomp_is_syscall_allowed(__NR_execve));
                REQUIRE_FALSE(merovingian::platform::worker_seccomp_is_syscall_allowed(__NR_execve));
#ifdef __NR_execveat
                REQUIRE(merovingian::platform::seccomp_is_syscall_allowed(__NR_execveat));
                REQUIRE_FALSE(merovingian::platform::worker_seccomp_is_syscall_allowed(__NR_execveat));
#endif
                // Spot-check that a representative worker-allowed syscall is also
                // main-allowed (subset relationship for these samples).
                REQUIRE(merovingian::platform::seccomp_is_syscall_allowed(__NR_connect));
                REQUIRE(merovingian::platform::seccomp_is_syscall_allowed(__NR_mlock));
            }
        }
    }
}

// M-08: the thumbnail decoder runs untrusted image data through libpng and
// libjpeg-turbo. The BSD branches of thumbnail_worker_main.cpp::harden()
// confine it with pledge("stdio") / cap_enter(), which grant no filesystem,
// socket, exec or process-creation access. The Linux branch previously
// installed the general server filter, which permits all four. The decoder
// profile is the seccomp equivalent of pledge("stdio"): work on already-open
// descriptors only.
SCENARIO("worker seccomp filter restricts process-control syscalls",
         "[platform][hardening][seccomp][worker][linux][iso-2]")
{
    GIVEN("the worker seccomp allowlist")
    {
        WHEN("signal and resource-limit syscalls are checked")
        {
            THEN("kill, tkill and setrlimit are denied")
            {
                // ISO-2: the worker never needs to send signals to arbitrary
                // processes or change its own resource limits. Allowing these
                // would let a compromised worker manipulate the process table or
                // relax sandbox limits.
                REQUIRE_FALSE(merovingian::platform::worker_seccomp_is_syscall_allowed(__NR_kill));
#ifdef __NR_tkill
                REQUIRE_FALSE(merovingian::platform::worker_seccomp_is_syscall_allowed(__NR_tkill));
#endif
#ifdef __NR_setrlimit
                REQUIRE_FALSE(merovingian::platform::worker_seccomp_is_syscall_allowed(__NR_setrlimit));
#endif
            }

            AND_THEN("tgkill and prlimit64 are listed, for the argument-checked uses the worker needs")
            {
                // The static predicate checks the syscall number only. The
                // installed BPF filter allows tgkill only on the worker's own
                // thread group, and prlimit64 only to read the worker's own
                // limits (glibc's getrlimit(); thread creation needs it). Those
                // argument checks are tested against the real kernel in [iso2],
                // tests/unit/test_worker_hardening_threads.cpp.
                REQUIRE(merovingian::platform::worker_seccomp_is_syscall_allowed(__NR_tgkill));
#ifdef __NR_prlimit64
                REQUIRE(merovingian::platform::worker_seccomp_is_syscall_allowed(__NR_prlimit64));
#endif
            }
        }
    }
}

SCENARIO("decoder seccomp filter confines the thumbnail worker to the stdio "
         "boundary",
         "[platform][hardening][seccomp][linux][media]")
{
    GIVEN("the decoder seccomp allowlist constants")
    {
        WHEN("the default action is queried")
        {
            auto const action = merovingian::platform::decoder_seccomp_default_action();

            THEN("it is SECCOMP_RET_KILL_PROCESS (fail-closed)")
            {
                REQUIRE(action == static_cast<std::uint32_t>(SECCOMP_RET_KILL_PROCESS));
            }
        }

        WHEN("the syscalls a decoder needs on already-open descriptors are "
             "checked")
        {
            THEN("stdio reads and writes, memory management, and exit are allowed")
            {
                // The worker reads the request from stdin and writes the encoded
                // thumbnail to stdout; both descriptors are already open when the
                // filter is installed.
                REQUIRE(merovingian::platform::decoder_seccomp_is_syscall_allowed(__NR_read));
                REQUIRE(merovingian::platform::decoder_seccomp_is_syscall_allowed(__NR_write));
                REQUIRE(merovingian::platform::decoder_seccomp_is_syscall_allowed(__NR_readv));
                REQUIRE(merovingian::platform::decoder_seccomp_is_syscall_allowed(__NR_writev));
                REQUIRE(merovingian::platform::decoder_seccomp_is_syscall_allowed(__NR_lseek));
                REQUIRE(merovingian::platform::decoder_seccomp_is_syscall_allowed(__NR_close));
                REQUIRE(merovingian::platform::decoder_seccomp_is_syscall_allowed(__NR_fstat));
                // libpng and libjpeg-turbo allocate freely while decoding.
                REQUIRE(merovingian::platform::decoder_seccomp_is_syscall_allowed(__NR_mmap));
                REQUIRE(merovingian::platform::decoder_seccomp_is_syscall_allowed(__NR_munmap));
                REQUIRE(merovingian::platform::decoder_seccomp_is_syscall_allowed(__NR_mprotect));
                REQUIRE(merovingian::platform::decoder_seccomp_is_syscall_allowed(__NR_brk));
                REQUIRE(merovingian::platform::decoder_seccomp_is_syscall_allowed(__NR_mremap));
                REQUIRE(merovingian::platform::decoder_seccomp_is_syscall_allowed(__NR_madvise));
                REQUIRE(merovingian::platform::decoder_seccomp_is_syscall_allowed(__NR_exit));
                REQUIRE(merovingian::platform::decoder_seccomp_is_syscall_allowed(__NR_exit_group));
                REQUIRE(merovingian::platform::decoder_seccomp_is_syscall_allowed(__NR_rt_sigreturn));
            }
        }

        WHEN("the glibc malloc fast-path per-thread syscalls are checked")
        {
            THEN("futex, rseq, membarrier, and getcpu are allowed")
            {
                // Same rationale as the main filter: glibc 2.35+ issues rseq,
                // membarrier, and getcpu from inside malloc. Omitting them would
                // kill the worker on the first allocation, not on an escape attempt.
                REQUIRE(merovingian::platform::decoder_seccomp_is_syscall_allowed(__NR_futex));
                REQUIRE(merovingian::platform::decoder_seccomp_is_syscall_allowed(334)); // rseq
                REQUIRE(merovingian::platform::decoder_seccomp_is_syscall_allowed(324)); // membarrier
                REQUIRE(merovingian::platform::decoder_seccomp_is_syscall_allowed(309)); // getcpu
            }
        }

        WHEN("network syscalls are checked")
        {
            THEN("the decoder cannot create or use sockets")
            {
                // A decoder exploit must not be able to exfiltrate media, reach the
                // federation network, or call home. This is the property
                // pledge("stdio") gives on OpenBSD and cap_enter() gives on FreeBSD.
                REQUIRE_FALSE(merovingian::platform::decoder_seccomp_is_syscall_allowed(__NR_socket));
                REQUIRE_FALSE(merovingian::platform::decoder_seccomp_is_syscall_allowed(__NR_socketpair));
                REQUIRE_FALSE(merovingian::platform::decoder_seccomp_is_syscall_allowed(__NR_connect));
                REQUIRE_FALSE(merovingian::platform::decoder_seccomp_is_syscall_allowed(__NR_bind));
                REQUIRE_FALSE(merovingian::platform::decoder_seccomp_is_syscall_allowed(__NR_listen));
                REQUIRE_FALSE(merovingian::platform::decoder_seccomp_is_syscall_allowed(__NR_accept));
                REQUIRE_FALSE(merovingian::platform::decoder_seccomp_is_syscall_allowed(__NR_accept4));
                REQUIRE_FALSE(merovingian::platform::decoder_seccomp_is_syscall_allowed(__NR_sendto));
                REQUIRE_FALSE(merovingian::platform::decoder_seccomp_is_syscall_allowed(__NR_recvfrom));
                REQUIRE_FALSE(merovingian::platform::decoder_seccomp_is_syscall_allowed(__NR_sendmsg));
                REQUIRE_FALSE(merovingian::platform::decoder_seccomp_is_syscall_allowed(__NR_recvmsg));
            }
        }

        WHEN("process-creation syscalls are checked")
        {
            THEN("the decoder cannot exec or fork")
            {
                REQUIRE_FALSE(merovingian::platform::decoder_seccomp_is_syscall_allowed(__NR_execve));
#ifdef __NR_execveat
                REQUIRE_FALSE(merovingian::platform::decoder_seccomp_is_syscall_allowed(__NR_execveat));
#endif
                REQUIRE_FALSE(merovingian::platform::decoder_seccomp_is_syscall_allowed(__NR_clone));
                REQUIRE_FALSE(merovingian::platform::decoder_seccomp_is_syscall_allowed(435)); // clone3
#ifdef __NR_fork
                REQUIRE_FALSE(merovingian::platform::decoder_seccomp_is_syscall_allowed(__NR_fork));
#endif
#ifdef __NR_vfork
                REQUIRE_FALSE(merovingian::platform::decoder_seccomp_is_syscall_allowed(__NR_vfork));
#endif
                REQUIRE_FALSE(merovingian::platform::decoder_seccomp_is_syscall_allowed(__NR_ptrace));
            }
        }

        WHEN("path-based filesystem syscalls are checked")
        {
            THEN("the decoder cannot open, create, or unlink anything by name")
            {
                // The worker is handed its input on stdin. It never needs to name a
                // file, so opening one is always an escape attempt.
                REQUIRE_FALSE(merovingian::platform::decoder_seccomp_is_syscall_allowed(__NR_openat));
#ifdef __NR_open
                REQUIRE_FALSE(merovingian::platform::decoder_seccomp_is_syscall_allowed(__NR_open));
#endif
#ifdef __NR_openat2
                REQUIRE_FALSE(merovingian::platform::decoder_seccomp_is_syscall_allowed(__NR_openat2));
#endif
                REQUIRE_FALSE(merovingian::platform::decoder_seccomp_is_syscall_allowed(__NR_unlinkat));
                REQUIRE_FALSE(merovingian::platform::decoder_seccomp_is_syscall_allowed(__NR_renameat));
                REQUIRE_FALSE(merovingian::platform::decoder_seccomp_is_syscall_allowed(__NR_mkdirat));
                REQUIRE_FALSE(merovingian::platform::decoder_seccomp_is_syscall_allowed(__NR_chdir));
                REQUIRE_FALSE(merovingian::platform::decoder_seccomp_is_syscall_allowed(__NR_getdents64));
            }
        }

        WHEN("the decoder profile is compared with the federation worker profile")
        {
            THEN("it is strictly tighter - the worker profile permits network and "
                 "process syscalls it denies")
            {
                // Guards against someone "simplifying" the decoder onto the worker
                // filter. The worker legitimately needs sockets and threads for
                // federation HTTP; a media decoder needs neither, and reusing that
                // profile would silently reopen this finding.
                REQUIRE(merovingian::platform::worker_seccomp_is_syscall_allowed(__NR_socket));
                REQUIRE_FALSE(merovingian::platform::decoder_seccomp_is_syscall_allowed(__NR_socket));
                REQUIRE(merovingian::platform::worker_seccomp_is_syscall_allowed(__NR_openat));
                REQUIRE_FALSE(merovingian::platform::decoder_seccomp_is_syscall_allowed(__NR_openat));
                REQUIRE(merovingian::platform::worker_seccomp_is_syscall_allowed(__NR_clone));
                REQUIRE_FALSE(merovingian::platform::decoder_seccomp_is_syscall_allowed(__NR_clone));
            }
        }
    }
}
#endif // __linux__
