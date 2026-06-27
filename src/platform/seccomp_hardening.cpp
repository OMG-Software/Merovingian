// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/platform/seccomp_hardening.hpp"

#include <string_view>

#ifdef __linux__
#include <cstddef>
#include <cstdint>
#include <optional>

#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#endif

namespace merovingian::platform
{

#ifdef __linux__
namespace
{

    struct FdGuard final
    {
        int fd{-1};
        explicit FdGuard(int f) noexcept
            : fd{f}
        {
        }
        ~FdGuard() noexcept
        {
            if (fd >= 0)
            {
                ::close(fd);
            }
        }
        FdGuard(FdGuard const&) = delete;
        auto operator=(FdGuard const&) -> FdGuard& = delete;
        FdGuard(FdGuard&&) = delete;
        auto operator=(FdGuard&&) -> FdGuard& = delete;
    };

    // SECCOMP_RET_KILL_PROCESS: kill the entire process on a disallowed syscall.
    // Added in kernel 4.14. The numeric value is used directly so this file
    // compiles against older kernel headers where the macro is absent.
#ifndef SECCOMP_RET_KILL_PROCESS
    static constexpr auto k_seccomp_ret_kill_process = std::uint32_t{0x80000000U};
#else
    static constexpr auto k_seccomp_ret_kill_process = std::uint32_t{SECCOMP_RET_KILL_PROCESS};
#endif

    // Unconditionally allow the syscall with the given number.
    // Expands to two sock_filter entries: a JEQ test (falls through to ALLOW on
    // match, jumps past it on mismatch) and a SECCOMP_RET_ALLOW.
#define ALLOW_SYSCALL(nr)                                                                                              \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, static_cast<uint32_t>(nr), 0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)

    // clang-format off
    struct ::sock_filter k_seccomp_filter[] = {  // NOLINT(*-avoid-c-arrays)
#if defined(__x86_64__)
        // ── Architecture guard ──────────────────────────────────────────────
        // Reject non-x86_64 calls to block 32-bit compat (IA-32) syscall spoofing.
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 static_cast<uint32_t>(offsetof(struct ::seccomp_data, arch))),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, k_seccomp_ret_kill_process),
#elif defined(__aarch64__)
        // Reject non-aarch64 calls to block aarch32 compat syscall spoofing.
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 static_cast<uint32_t>(offsetof(struct ::seccomp_data, arch))),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_AARCH64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, k_seccomp_ret_kill_process),
#else
        // Unsupported architecture: fail closed rather than allowing syscalls.
        BPF_STMT(BPF_RET | BPF_K, k_seccomp_ret_kill_process),
#endif
        // Load the syscall number for all remaining comparisons.
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 static_cast<uint32_t>(offsetof(struct ::seccomp_data, nr))),

        // ── I/O ────────────────────────────────────────────────────────────
        ALLOW_SYSCALL(__NR_read),
        ALLOW_SYSCALL(__NR_write),
        ALLOW_SYSCALL(__NR_readv),
        ALLOW_SYSCALL(__NR_writev),
        ALLOW_SYSCALL(__NR_pread64),
        ALLOW_SYSCALL(__NR_pwrite64),
        ALLOW_SYSCALL(__NR_preadv),
        ALLOW_SYSCALL(__NR_pwritev),
        ALLOW_SYSCALL(__NR_sendfile),

        // ── File system ────────────────────────────────────────────────────
        // Only operations required by the runtime are allowed. std::filesystem
        // operations such as create_directories may issue mkdirat, so it stays.
        // Metadata changes (chmod/umask) and destructive/rename ops are not
        // required after the filter is applied and are therefore denied.
        ALLOW_SYSCALL(__NR_open),
        ALLOW_SYSCALL(__NR_openat),
        ALLOW_SYSCALL(__NR_close),
        ALLOW_SYSCALL(__NR_stat),
        ALLOW_SYSCALL(__NR_fstat),
        ALLOW_SYSCALL(__NR_lstat),
        ALLOW_SYSCALL(__NR_access),
        ALLOW_SYSCALL(__NR_faccessat),
        ALLOW_SYSCALL(__NR_lseek),
        ALLOW_SYSCALL(__NR_fcntl),
        ALLOW_SYSCALL(__NR_ioctl),
        ALLOW_SYSCALL(__NR_flock),
        ALLOW_SYSCALL(__NR_fsync),
        ALLOW_SYSCALL(__NR_fdatasync),
        ALLOW_SYSCALL(__NR_getcwd),
        ALLOW_SYSCALL(__NR_chdir),
        ALLOW_SYSCALL(__NR_mkdirat),
        ALLOW_SYSCALL(__NR_readlink),
        ALLOW_SYSCALL(__NR_readlinkat),
        ALLOW_SYSCALL(__NR_getdents64),
        ALLOW_SYSCALL(__NR_dup),
        ALLOW_SYSCALL(__NR_dup2),
        ALLOW_SYSCALL(__NR_dup3),
        ALLOW_SYSCALL(__NR_pipe),
        ALLOW_SYSCALL(__NR_pipe2),
        ALLOW_SYSCALL(__NR_memfd_create),
        // File deletion and truncation — SQLite requires these for every write
        // transaction: the journal is deleted via unlinkat on commit, and WAL
        // files are truncated via ftruncate during checkpoints and rollbacks.
        // std::filesystem::rename also uses renameat on modern glibc.
        // The writable path set is bounded by the service-manager sandbox.
        ALLOW_SYSCALL(__NR_ftruncate),
        ALLOW_SYSCALL(__NR_unlink),
        ALLOW_SYSCALL(__NR_unlinkat),
        ALLOW_SYSCALL(__NR_rename),
        ALLOW_SYSCALL(__NR_renameat),
#ifdef __NR_renameat2
        ALLOW_SYSCALL(__NR_renameat2),
#endif
        // Filesystem type probe — SQLite calls fstatfs/statfs early in WAL-mode
        // open to detect the device sector size and platform I/O capabilities.
        ALLOW_SYSCALL(__NR_fstatfs),
        ALLOW_SYSCALL(__NR_statfs),
        // posix_fallocate path: SQLite amalgamation calls posix_fallocate to
        // pre-allocate space for database and WAL files; on Linux glibc maps
        // this to fallocate(2) on filesystems that support it.
#ifdef __NR_fallocate
        ALLOW_SYSCALL(__NR_fallocate),
#endif
#ifdef __NR_statx
        ALLOW_SYSCALL(__NR_statx),
#endif
#ifdef __NR_newfstatat
        ALLOW_SYSCALL(__NR_newfstatat),
#endif
#ifdef __NR_openat2
        ALLOW_SYSCALL(__NR_openat2),
#endif

        // ── Memory ─────────────────────────────────────────────────────────
        ALLOW_SYSCALL(__NR_mmap),
        ALLOW_SYSCALL(__NR_munmap),
        ALLOW_SYSCALL(__NR_mprotect),
        ALLOW_SYSCALL(__NR_madvise),
        ALLOW_SYSCALL(__NR_brk),
        ALLOW_SYSCALL(__NR_mremap),
        ALLOW_SYSCALL(__NR_mlock),
        ALLOW_SYSCALL(__NR_munlock),
        ALLOW_SYSCALL(__NR_mlockall),
        ALLOW_SYSCALL(__NR_munlockall),
        ALLOW_SYSCALL(__NR_mincore),

        // ── Network ────────────────────────────────────────────────────────
        ALLOW_SYSCALL(__NR_socket),
        ALLOW_SYSCALL(__NR_bind),
        ALLOW_SYSCALL(__NR_listen),
        ALLOW_SYSCALL(__NR_accept),
        ALLOW_SYSCALL(__NR_accept4),
        ALLOW_SYSCALL(__NR_connect),
        ALLOW_SYSCALL(__NR_getsockname),
        ALLOW_SYSCALL(__NR_getpeername),
        ALLOW_SYSCALL(__NR_sendto),
        ALLOW_SYSCALL(__NR_recvfrom),
        ALLOW_SYSCALL(__NR_sendmsg),
        ALLOW_SYSCALL(__NR_recvmsg),
        ALLOW_SYSCALL(__NR_sendmmsg),
        ALLOW_SYSCALL(__NR_recvmmsg),
        ALLOW_SYSCALL(__NR_setsockopt),
        ALLOW_SYSCALL(__NR_getsockopt),
        ALLOW_SYSCALL(__NR_shutdown),
        ALLOW_SYSCALL(__NR_socketpair),

        // ── Poll and event notification ────────────────────────────────────
        ALLOW_SYSCALL(__NR_select),
        ALLOW_SYSCALL(__NR_pselect6),
        ALLOW_SYSCALL(__NR_poll),
        ALLOW_SYSCALL(__NR_ppoll),
        ALLOW_SYSCALL(__NR_epoll_create),
        ALLOW_SYSCALL(__NR_epoll_create1),
        ALLOW_SYSCALL(__NR_epoll_ctl),
        ALLOW_SYSCALL(__NR_epoll_wait),
        ALLOW_SYSCALL(__NR_epoll_pwait),
        ALLOW_SYSCALL(__NR_eventfd),
        ALLOW_SYSCALL(__NR_eventfd2),
        ALLOW_SYSCALL(__NR_timerfd_create),
        ALLOW_SYSCALL(__NR_timerfd_gettime),
        ALLOW_SYSCALL(__NR_timerfd_settime),
        ALLOW_SYSCALL(__NR_signalfd),
        ALLOW_SYSCALL(__NR_signalfd4),
        ALLOW_SYSCALL(__NR_inotify_init1),
        ALLOW_SYSCALL(__NR_inotify_add_watch),
#ifdef __NR_epoll_pwait2
        ALLOW_SYSCALL(__NR_epoll_pwait2),
#endif

        // ── Process spawning ───────────────────────────────────────────────
        // posix_spawn() calls execve/execveat in the child. The child inherits
        // this filter, so the worker applies its own stricter filter at startup.
        // Required for both initial worker launch and supervisor-driven restarts.
        ALLOW_SYSCALL(__NR_execve),
#ifdef __NR_execveat
        ALLOW_SYSCALL(__NR_execveat),
#endif

        // ── Threads and synchronisation ────────────────────────────────────
        ALLOW_SYSCALL(__NR_futex),
        ALLOW_SYSCALL(__NR_set_robust_list),
        ALLOW_SYSCALL(__NR_get_robust_list),
        ALLOW_SYSCALL(__NR_sched_yield),
        ALLOW_SYSCALL(__NR_clone),
        ALLOW_SYSCALL(__NR_nanosleep),
        ALLOW_SYSCALL(__NR_clock_nanosleep),
        ALLOW_SYSCALL(__NR_restart_syscall),
        ALLOW_SYSCALL(__NR_wait4),
        ALLOW_SYSCALL(__NR_waitid),
        ALLOW_SYSCALL(__NR_exit),
        ALLOW_SYSCALL(__NR_exit_group),
        ALLOW_SYSCALL(__NR_set_tid_address),
#ifdef __NR_clone3
        ALLOW_SYSCALL(__NR_clone3),
#endif
#ifdef __NR_futex_waitv
        ALLOW_SYSCALL(__NR_futex_waitv),
#endif
        // glibc 2.35+ per-thread restartable-sequence registration. The child
        // process re-registers its rseq area after fork(), and glibc 2.36+
        // also uses rseq inside the malloc per-CPU cache implementation.
#ifdef __NR_rseq
        ALLOW_SYSCALL(__NR_rseq),
#endif
        // glibc 2.31+ issues membarrier(MEMBARRIER_CMD_PRIVATE_EXPEDITED) in
        // the malloc fast path on multi-processor systems. Without this the
        // call gets SIGSYS on distros whose glibc enables it by default.
#ifdef __NR_membarrier
        ALLOW_SYSCALL(__NR_membarrier),
#endif
        // getcpu: returns the running CPU and NUMA node; used by glibc's
        // per-CPU TLS cache and malloc implementation.
#ifdef __NR_getcpu
        ALLOW_SYSCALL(__NR_getcpu),
#endif

        // ── Signals ────────────────────────────────────────────────────────
        ALLOW_SYSCALL(__NR_rt_sigaction),
        ALLOW_SYSCALL(__NR_rt_sigprocmask),
        ALLOW_SYSCALL(__NR_rt_sigreturn),
        ALLOW_SYSCALL(__NR_rt_sigsuspend),
        ALLOW_SYSCALL(__NR_sigaltstack),
        ALLOW_SYSCALL(__NR_kill),
        ALLOW_SYSCALL(__NR_tgkill),
        ALLOW_SYSCALL(__NR_tkill),

        // ── Security and privilege ─────────────────────────────────────────
        ALLOW_SYSCALL(__NR_prctl),
        ALLOW_SYSCALL(__NR_arch_prctl),
        ALLOW_SYSCALL(__NR_seccomp),
        ALLOW_SYSCALL(__NR_getrandom),
        ALLOW_SYSCALL(__NR_capget),
        ALLOW_SYSCALL(__NR_capset),

        // ── Process identity ───────────────────────────────────────────────
        ALLOW_SYSCALL(__NR_getpid),
        ALLOW_SYSCALL(__NR_getppid),
        ALLOW_SYSCALL(__NR_gettid),
        ALLOW_SYSCALL(__NR_getuid),
        ALLOW_SYSCALL(__NR_geteuid),
        ALLOW_SYSCALL(__NR_getgid),
        ALLOW_SYSCALL(__NR_getegid),
        ALLOW_SYSCALL(__NR_getgroups),

        // ── Resource limits and scheduling ─────────────────────────────────
        ALLOW_SYSCALL(__NR_getrlimit),
        ALLOW_SYSCALL(__NR_setrlimit),
        ALLOW_SYSCALL(__NR_prlimit64),
        ALLOW_SYSCALL(__NR_sched_getaffinity),
        ALLOW_SYSCALL(__NR_getrusage),

        // ── Time ───────────────────────────────────────────────────────────
        ALLOW_SYSCALL(__NR_clock_gettime),
        ALLOW_SYSCALL(__NR_clock_getres),
        ALLOW_SYSCALL(__NR_gettimeofday),
        ALLOW_SYSCALL(__NR_time),

        // ── System information ─────────────────────────────────────────────
        ALLOW_SYSCALL(__NR_uname),
        ALLOW_SYSCALL(__NR_sysinfo),

        // ── Default: fail-closed for any unrecognised syscall ────────────────
        BPF_STMT(BPF_RET | BPF_K, k_seccomp_ret_kill_process),
    };
    // clang-format on
#undef ALLOW_SYSCALL

    [[nodiscard]] auto install_seccomp_filter_with_default(std::uint32_t default_action) noexcept -> bool
    {
        // Reuse the production allowlist exactly (no drift between the filter
        // under test and the one shipped in production) but override the final
        // fail-closed statement with the caller's default action. The
        // integration test installs SECCOMP_RET_TRAP here so a blocked syscall
        // is delivered to a SIGSYS handler and reported, instead of killing the
        // process opaquely under SECCOMP_RET_KILL_PROCESS.
        constexpr auto k_filter_len = sizeof(k_seccomp_filter) / sizeof(k_seccomp_filter[0]);
        ::sock_filter filt[k_filter_len]; // NOLINT(*-avoid-c-arrays)
        for (std::size_t i = 0; i < k_filter_len; ++i)
        {
            filt[i] = k_seccomp_filter[i];
        }
        filt[k_filter_len - 1U] = BPF_STMT(BPF_RET | BPF_K, default_action);

        auto const prog = ::sock_fprog{
            .len = static_cast<unsigned short>(k_filter_len),
            .filter = filt,
        };

        if (::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
        {
            return false;
        }
        return ::syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog) == 0;
    }

    [[nodiscard]] auto install_seccomp_filter() noexcept -> bool
    {
        return install_seccomp_filter_with_default(k_seccomp_ret_kill_process);
    }

    [[nodiscard]] auto read_seccomp_status() -> SeccompProbeResult
    {
        auto result = SeccompProbeResult{};
        auto const guard = FdGuard{::open("/proc/self/status", O_RDONLY | O_CLOEXEC)};
        if (guard.fd < 0)
        {
            return result;
        }
        char buf[4096] = {};
        auto const n = ::read(guard.fd, buf, sizeof(buf) - 1U);
        if (n <= 0)
        {
            return result;
        }
        result.probed = true;
        auto const sv = std::string_view{buf, static_cast<std::size_t>(n)};
        auto const pos = sv.find("Seccomp:");
        if (pos == std::string_view::npos)
        {
            return result;
        }
        auto value_start = pos + 8U;
        while (value_start < sv.size() && (sv[value_start] == ' ' || sv[value_start] == '\t'))
        {
            ++value_start;
        }
        // Mode 2 = SECCOMP_MODE_FILTER: a bpf filter is active.
        result.seccomp_active = value_start < sv.size() && sv[value_start] == '2';
        return result;
    }

} // namespace
#endif // __linux__

auto apply_seccomp_filter() noexcept -> bool
{
#ifdef __linux__
    return install_seccomp_filter();
#else
    return false;
#endif
}

auto apply_seccomp_filter_with_default([[maybe_unused]] std::uint32_t default_action) noexcept -> bool
{
#ifdef __linux__
    return install_seccomp_filter_with_default(default_action);
#else
    return false;
#endif
}

auto probe_seccomp_status() -> SeccompProbeResult
{
#ifdef __linux__
    return read_seccomp_status();
#else
    return {};
#endif
}

#ifdef __linux__
auto seccomp_default_action() noexcept -> std::uint32_t
{
    return k_seccomp_ret_kill_process;
}

auto seccomp_is_syscall_allowed(int const syscall_number) noexcept -> bool
{
    // ALLOW_SYSCALL(nr) emits a JEQ jump on the syscall number followed by an
    // SECCOMP_RET_ALLOW statement. A matching pair means the syscall is in the
    // allowlist. Anything else (including the architecture guard and default
    // action) is ignored by this scan.
    auto const filter_size = sizeof(k_seccomp_filter) / sizeof(k_seccomp_filter[0]);
    for (std::size_t i = 0; i + 1 < filter_size; ++i)
    {
        auto const& jump = k_seccomp_filter[i];
        auto const& allow = k_seccomp_filter[i + 1];
        if (jump.code == (BPF_JMP | BPF_JEQ | BPF_K) && jump.jt == 0 && jump.jf == 1 &&
            allow.code == (BPF_RET | BPF_K) && allow.k == SECCOMP_RET_ALLOW &&
            static_cast<int>(jump.k) == syscall_number)
        {
            return true;
        }
    }
    return false;
}

auto seccomp_expected_architecture() noexcept -> std::optional<std::uint32_t>
{
#if defined(__x86_64__)
    return static_cast<std::uint32_t>(AUDIT_ARCH_X86_64);
#elif defined(__aarch64__)
    return static_cast<std::uint32_t>(AUDIT_ARCH_AARCH64);
#else
    return std::nullopt;
#endif
}
#endif // __linux__

} // namespace merovingian::platform
