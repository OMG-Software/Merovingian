// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

namespace merovingian::platform
{

struct SeccompProbeResult final
{
    bool probed{false};               // true when at least one task's status was read successfully
    bool seccomp_active{false};       // true when EVERY task reports Seccomp: 2 and NoNewPrivs: 1
    std::size_t tasks_checked{0U};    // tasks whose status was read
    std::size_t unconfined_tasks{0U}; // tasks that were not confined, or whose status was unreadable
};

// What one /proc/<pid>/task/<tid>/status says about a single task's seccomp
// confinement. Seccomp filters and no_new_privs are per-task attributes, so a
// process is only confined when every task is.
struct TaskConfinement final
{
    bool parsed{false};   // both fields were present and numeric
    int seccomp_mode{-1}; // 0 disabled, 1 strict, 2 filter
    int no_new_privs{-1}; // 0 or 1

    // Fail-closed: a task that could not be fully parsed is never confined.
    [[nodiscard]] constexpr auto confined() const noexcept -> bool
    {
        return parsed && seccomp_mode == 2 && no_new_privs == 1;
    }
};

// Parses the "Seccomp:" and "NoNewPrivs:" lines of a /proc status file. Pure
// text handling, available on every platform so it can be tested anywhere.
[[nodiscard]] auto parse_task_confinement(std::string_view status_text) noexcept -> TaskConfinement;

// Applies a seccomp-bpf syscall allowlist to the calling process via
// prctl(PR_SET_NO_NEW_PRIVS) + seccomp(SECCOMP_SET_MODE_FILTER).
//
// EVERY filter installer in this header (main, worker and decoder profiles, and
// their *_with_default variants) passes SECCOMP_FILTER_FLAG_TSYNC, so a thread
// that already exists is confined by the same call (ISO-1, ADR-0082). A TSYNC
// failure is a failure of the installer; there is no per-thread fallback. TSYNC
// is defence in depth: callers must still start no thread before hardening,
// because Landlock has no equivalent.
// Must be called before listeners bind and before run_startup_hardening_self_check().
// The default action is SECCOMP_RET_KILL_PROCESS: any syscall not in the allowlist
// kills the calling process immediately (fail-closed).
// On non-Linux or kernels without CONFIG_SECCOMP_FILTER, returns false;
// the hardening self-check probe then reports `unknown`.
[[nodiscard]] auto apply_seccomp_filter() noexcept -> bool;

// Applies the same syscall allowlist as apply_seccomp_filter() but with a
// caller-chosen default action for syscalls not on the list. Exposed so the
// integration test can install SECCOMP_RET_TRAP plus a SIGSYS handler and
// report the exact blocked syscall number instead of dying opaquely under
// SECCOMP_RET_KILL_PROCESS, which makes allowlist gaps diagnosable. Production
// code must use apply_seccomp_filter(); only tests pass a non-kill default.
[[nodiscard]] auto apply_seccomp_filter_with_default(std::uint32_t default_action) noexcept -> bool;

// Applies a STRICTER allowlist for the federation worker child (issue #319).
// The worker never spawns or execs child processes, so execve/execveat are
// DENIED here even though the main process allows them (for posix_spawn). All
// other syscalls the worker needs (I/O, threads, network, mlock, getrandom)
// match the main allowlist. Same fail-closed default action. Returns false on
// non-Linux or kernels without CONFIG_SECCOMP_FILTER.
[[nodiscard]] auto apply_worker_seccomp_filter() noexcept -> bool;

// Worker-filter variant with a caller-chosen default action, for the same
// diagnosability reason as apply_seccomp_filter_with_default(). Production
// worker code must use apply_worker_seccomp_filter().
[[nodiscard]] auto apply_worker_seccomp_filter_with_default(std::uint32_t default_action) noexcept -> bool;

// Applies the DECODER allowlist for the thumbnail worker child (M-08). This is
// the seccomp equivalent of the pledge("stdio") / cap_enter() calls the BSD
// branches of media/thumbnail_worker_main.cpp::harden() make: I/O on
// already-open descriptors, memory, and exit — no sockets, no path-based
// filesystem access, no exec, no fork/clone.
//
// It is NOT apply_worker_seccomp_filter(). That profile serves the federation
// worker, which needs sockets and threads and therefore permits both; installing
// it here would leave a compromised image decoder able to open files and connect
// out. Same fail-closed default action. Returns false on non-Linux or kernels
// without CONFIG_SECCOMP_FILTER.
[[nodiscard]] auto apply_decoder_seccomp_filter() noexcept -> bool;

// Decoder-filter variant with a caller-chosen default action, for the same
// diagnosability reason as apply_seccomp_filter_with_default(). Production
// decoder code must use apply_decoder_seccomp_filter().
[[nodiscard]] auto apply_decoder_seccomp_filter_with_default(std::uint32_t default_action) noexcept -> bool;

// Reads /proc/self/task/<tid>/status for EVERY task in the process and reports
// whether all of them have a seccomp-bpf filter ("Seccomp: 2") and
// no_new_privs ("NoNewPrivs: 1"). /proc/self/status describes only the
// thread-group leader, so it cannot see an unconfined sibling thread (ISO-1).
// A task that exits while the directory is being walked is ignored; any other
// unreadable or unparsable task counts as unconfined. Returns probed=false on
// non-Linux, or when no task could be read.
[[nodiscard]] auto probe_seccomp_status() -> SeccompProbeResult;

#ifdef __linux__
// Returns the default seccomp-bpf action used by apply_seccomp_filter().
// Fail-closed: SECCOMP_RET_KILL_PROCESS.
[[nodiscard]] auto seccomp_default_action() noexcept -> std::uint32_t;

// Returns true if `syscall_number` is present in the allowlist used by
// apply_seccomp_filter(). Exposed for unit testing without installing the
// filter in the test process.
[[nodiscard]] auto seccomp_is_syscall_allowed(int syscall_number) noexcept -> bool;

// Returns the default seccomp-bpf action used by apply_worker_seccomp_filter().
// Fail-closed: SECCOMP_RET_KILL_PROCESS (same as the main filter).
[[nodiscard]] auto worker_seccomp_default_action() noexcept -> std::uint32_t;

// Returns true if `syscall_number` is present in the worker allowlist used by
// apply_worker_seccomp_filter(). Exposed for unit testing the stricter profile
// (execve/execveat must be denied; the thread/network/I/O set must be allowed).
[[nodiscard]] auto worker_seccomp_is_syscall_allowed(int syscall_number) noexcept -> bool;

// Returns the default seccomp-bpf action used by apply_decoder_seccomp_filter().
// Fail-closed: SECCOMP_RET_KILL_PROCESS (same as the main filter).
[[nodiscard]] auto decoder_seccomp_default_action() noexcept -> std::uint32_t;

// Returns true if `syscall_number` is present in the decoder allowlist used by
// apply_decoder_seccomp_filter(). Exposed for unit testing the decoder profile
// (sockets, exec, fork/clone and path-based filesystem access must all be
// denied; the stdio/memory/exit set must be allowed).
[[nodiscard]] auto decoder_seccomp_is_syscall_allowed(int syscall_number) noexcept -> bool;

// Returns the AUDIT_ARCH_* constant the installed filter expects, or std::nullopt
// when the build architecture is not supported (fail-closed). Exposed for testing.
[[nodiscard]] auto seccomp_expected_architecture() noexcept -> std::optional<std::uint32_t>;
#endif

} // namespace merovingian::platform
