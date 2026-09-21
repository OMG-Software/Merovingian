// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/config/config_parser.hpp"
#include "merovingian/core/file_descriptor.hpp"
#include "merovingian/federation_worker/args.hpp"
#include "merovingian/observability/logger.hpp"
#include "merovingian/platform/landlock_hardening.hpp"
#include "merovingian/platform/runtime_hardening.hpp"
#include "worker_event_loop.hpp"

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>

#include <fcntl.h>
#include <signal.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/prctl.h>
#endif

#if defined(__SANITIZE_ADDRESS__) || (defined(__has_feature) && __has_feature(address_sanitizer))
// The federation worker runs under a strict seccomp filter (issue #319) that
// denies ptrace by design — ptrace is an escalation primitive a compromised
// worker must never possess. ASan's exit-time LeakSanitizer uses ptrace (via
// StopTheWorld) to suspend all threads before scanning for leaks; with ptrace
// denied, the tracer thread is killed and StopTheWorld spins in sched_yield
// forever, so the worker process never exits and the supervisor's wait4()
// hangs (the asan-ubsan CI integration timeout). Disable exit-time leak
// detection in the worker. The main process retains full ASan/LSan coverage of
// the shared code paths; the worker's own correctness is exercised by its unit
// and integration tests. Defined at global scope with C linkage so the ASan
// runtime resolves it as the weak default-options hook. ASAN_OPTIONS, when
// present in the environment, takes precedence over this default — the
// worker's minimal env (#330) carries no ASAN_OPTIONS, so this applies.
extern "C" auto __asan_default_options() -> char const* // NOLINT(readability-identifier-naming)
{
    return "detect_leaks=0";
}
#endif

namespace
{

auto read_file(std::string_view path) -> std::optional<std::string>
{
    auto input = std::ifstream{std::string{path}, std::ios::binary};
    if (!input.is_open())
    {
        return std::nullopt;
    }

    // Read in chunks to avoid a GCC -Wnull-dereference false positive that the
    // std::istreambuf_iterator constructor triggers in some libstdc++ builds.
    auto contents = std::string{};
    constexpr auto chunk_size = std::size_t{4096U};
    auto chunk = std::vector<char>(chunk_size);
    while (input.read(chunk.data(), static_cast<std::streamsize>(chunk.size())) || input.gcount() > 0)
    {
        contents.append(chunk.data(), static_cast<std::size_t>(input.gcount()));
    }
    input.close();
    return contents;
}

} // namespace

auto main(int argc, char const* const* argv) -> int
{
    auto const args = merovingian::federation_worker::parse_worker_args(argc, argv);
    if (args.error.has_value())
    {
        std::cerr << "merovingian-fed-worker: " << *args.error << '\n';
        return 1;
    }

    // Validate that the IPC fd is open.
    auto const raw_fd = *args.ipc_fd;
    if (::fcntl(raw_fd, F_GETFD) < 0)
    {
        std::cerr << "merovingian-fed-worker: ipc fd " << raw_fd << " is not open: " << ::strerror(errno) << '\n';
        return 1;
    }

    // Validate that the IPC auth key fd is open. It is consumed later, inside
    // WorkerEventLoop::run() (federation_worker::read_ipc_auth_key), after the
    // hardening sequence below is applied.
    auto const raw_key_fd = *args.ipc_key_fd;
    if (::fcntl(raw_key_fd, F_GETFD) < 0)
    {
        std::cerr << "merovingian-fed-worker: ipc key fd " << raw_key_fd << " is not open: " << ::strerror(errno)
                  << '\n';
        return 1;
    }

    // ADR-0062 part 2: validate the database-URI fd is open, when main
    // passed one. Absent is a valid, expected outcome (SQLite backend, or
    // the allow_shared_database_credentials opt-out) -- see
    // federation_worker::ParsedWorkerArgs::db_uri_fd. Also consumed later,
    // inside WorkerEventLoop::run() (federation_worker::read_worker_database_uri).
    auto const raw_db_uri_fd = args.db_uri_fd.has_value() ? *args.db_uri_fd : -1;
    if (args.db_uri_fd.has_value() && ::fcntl(raw_db_uri_fd, F_GETFD) < 0)
    {
        std::cerr << "merovingian-fed-worker: db-uri fd " << raw_db_uri_fd << " is not open: " << ::strerror(errno)
                  << '\n';
        return 1;
    }

    auto const contents = read_file(*args.config_path);
    if (!contents.has_value())
    {
        std::cerr << "merovingian-fed-worker: cannot open config: " << *args.config_path << '\n';
        return 1;
    }

    auto const parse_result = merovingian::config::parse_key_value_config(*contents);
    if (!parse_result.findings.empty())
    {
        for (auto const& f : parse_result.findings)
        {
            std::cerr << "merovingian-fed-worker: config: " << f.field << ": " << f.message << '\n';
        }
        return 1;
    }

    LOG_INFO("Federation worker starting: shard=" + std::to_string(args.shard_index) + " config=" + *args.config_path +
             " ipc_fd=" + std::to_string(raw_fd) + " ipc_key_fd=" + std::to_string(raw_key_fd) +
             (args.db_uri_fd.has_value() ? " db_uri_fd=" + std::to_string(raw_db_uri_fd) : ""));

#ifdef __linux__
    // Ask the kernel to terminate this child automatically if the parent thread
    // that spawned it exits. This prevents orphaned federation workers from
    // lingering when the main server process crashes or is killed.
    if (::prctl(PR_SET_PDEATHSIG, SIGTERM) != 0)
    {
        LOG_WARNING("Federation worker: prctl(PR_SET_PDEATHSIG, SIGTERM) failed: " + std::string{::strerror(errno)});
    }
#endif

    auto ipc_fd = merovingian::core::FileDescriptor{raw_fd};
    auto ipc_key_fd = merovingian::core::FileDescriptor{raw_key_fd};
    // Default-constructed (invalid) when main did not pass --db-uri-fd; see
    // WorkerEventLoop::run().
    auto db_uri_fd = args.db_uri_fd.has_value() ? merovingian::core::FileDescriptor{raw_db_uri_fd}
                                                : merovingian::core::FileDescriptor{};
    auto const threads = parse_result.config.federation_worker().threads;

    // ADR-0062 part 3: restrict the worker's own filesystem access with
    // Landlock before doing anything else that follows. Applied
    // unconditionally, independent of federation.worker.apply_hardening
    // (which gates only the seccomp/capability/core-dump sequence below) —
    // Landlock is a distinct security boundary from seccomp, and gating it
    // behind the same flag would let one opt-out silently disable both.
    // Landlock syscalls are not on the worker seccomp allowlist below, so
    // this must run first: either apply Landlock before the seccomp filter,
    // or add landlock_create_ruleset/landlock_add_rule/landlock_restrict_self
    // to that allowlist permanently. Applying first was chosen so the worker
    // seccomp allowlist never has to carry three syscalls it needs for one
    // startup step and never again.
    {
        auto const landlock_rules = merovingian::platform::build_worker_landlock_rules(parse_result.config);
        auto const landlock = merovingian::platform::apply_worker_landlock(
            landlock_rules, parse_result.config.federation_worker().allow_without_landlock);
        if (!landlock.accepted)
        {
            LOG_CRITICAL("Federation worker: Landlock filesystem restriction failed: " + landlock.reason);
            return 1;
        }
        if (landlock.critical_warning)
        {
            LOG_CRITICAL("Federation worker: " + landlock.reason);
        }
        else if (landlock.applied)
        {
            LOG_INFO("Federation worker: Landlock filesystem restriction applied (" +
                     std::to_string(landlock_rules.size()) + " path rules)");
        }
    }

    // Apply the worker-specific runtime hardening sequence (issue #319): core
    // dump policy, PR_SET_NO_NEW_PRIVS, capability-bounding drop, then the
    // worker seccomp-bpf filter (which denies execve/execveat — the worker never
    // spawns). Done after config is read and both fds are validated as open, but
    // before the event loop reads the IPC auth key, opens the DB, or starts
    // threads. The worker filter still allows read()/close()/open()/socket()/
    // clone() etc, so neither startup nor the key-fd read below is blocked.
    // Fail-closed: a failed control aborts the worker. The apply_hardening
    // config flag lets tests run the worker unfiltered while the allowlist
    // itself is validated in unit tests.
    if (parse_result.config.federation_worker().apply_hardening)
    {
        auto const hardening = merovingian::platform::apply_worker_hardening();
        if (!hardening.accepted)
        {
            LOG_CRITICAL("Federation worker: runtime hardening failed: " + hardening.reason);
            return 1;
        }
        LOG_INFO("Federation worker: runtime hardening applied (seccomp filter active)");
    }
    else
    {
        LOG_WARNING("Federation worker: runtime hardening disabled by config "
                    "(federation.worker.apply_hardening=false)");
    }

    auto loop = merovingian::federation_worker::WorkerEventLoop{
        std::move(ipc_fd), std::move(ipc_key_fd), std::move(db_uri_fd), parse_result.config, threads, args.shard_index};
    loop.run();

    return 0;
}
