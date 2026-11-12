// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "WorkerEventLoop.hpp"
#include "merovingian/config/ConfigParser.hpp"
#include "merovingian/core/FileDescriptor.hpp"
#include "merovingian/core/LibraryVersion.hpp"
#include "merovingian/federation_worker/ParsedWorkerArgs.hpp"
#include "merovingian/federation_worker/WorkerDatabaseConfig.hpp"
#include "merovingian/homeserver/LibraryVersions.hpp"
#include "merovingian/observability/SingleLog.hpp"
#include "merovingian/platform/LandlockHardening.hpp"
#include "merovingian/platform/RuntimeHardening.hpp"
#include "merovingian/platform/SignalHardening.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <iterator>
#include <optional>
#include <signal.h>
#include <string>
#include <string_view>
#include <tuple>

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
    std::ignore = ::umask(0077);
    // HTTP-5: ignore SIGPIPE before any thread exists and before seccomp is
    // installed. Fail closed.
    if (auto const sigpipe = merovingian::platform::ignore_sigpipe(); !sigpipe.accepted)
    {
        std::cerr << "merovingian-fed-worker: " << sigpipe.reason << '\n';
        return 1;
    }

    // ADR-0731: the worker must not share the terminal of the shell that started the server. Main spawns it in a
    // session of its own where the C library has POSIX_SPAWN_SETSID; elsewhere the worker leaves main's session here,
    // before it reads anything a remote server sent. A new session has no controlling terminal.
    if (::getsid(0) != ::getpid() && ::setsid() < 0)
    {
        std::cerr << "merovingian-fed-worker: cannot start a session of its own: " << std::strerror(errno) << '\n';
        return 1;
    }

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
             " ipc_fd=" + std::to_string(raw_fd) + " ipc_key_fd=" + std::to_string(raw_key_fd));
    // The worker is a separate executable and may load other copies of the libraries than the
    // server does, so it logs its own (0.12.45).
    for (auto const& library : merovingian::homeserver::linked_library_versions())
    {
        LOG_INFO("Federation worker library " + merovingian::core::library_version_log_line(library));
    }

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
    auto const threads = parse_result.config.federation_worker().threads;
    // ADR-0733: the worker opens no database; main sends it the rows it reads. Its copy of the configuration names no
    // database from here on, so the Landlock rules below grant no database directory and the runtime opens none.
    auto worker_config = parse_result.config;
    merovingian::federation_worker::clear_database_location(worker_config);

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
        auto const landlock_rules = merovingian::platform::build_worker_landlock_rules(worker_config);
        // Fail closed if any rule would grant access to a configured secret
        // (e.g. a master key placed beside the SQLite database, whose
        // directory is granted read-write). Refused even with
        // allow_without_landlock: this is a secret-placement error.
        if (auto const exposure = merovingian::platform::find_landlock_rule_covering_secret(
                // The secrets the operator configured, database URI files included, whatever the worker's copy says.
                landlock_rules, merovingian::platform::worker_landlock_secret_paths(parse_result.config));
            exposure.has_value())
        {
            LOG_CRITICAL("Federation worker: Landlock rule for '" + exposure->rule_path +
                         "' would grant the worker access to the secret '" + exposure->secret_path +
                         "'; move the secret out of that directory. Refusing to start.");
            return 1;
        }
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

    // ISO-1 / ADR-0082: no thread may exist before Landlock and the seccomp
    // filter above. The logger has written synchronously until now; start its
    // writer threads only here, so they inherit both restrictions. If they
    // cannot be started the logger stays synchronous, which is safe.
    if (!merovingian::observability::SingleLog::instance().start_writers())
    {
        LOG_WARNING("Federation worker: log writer threads could not be started; logging stays synchronous");
    }

    auto loop = merovingian::federation_worker::WorkerEventLoop{std::move(ipc_fd), std::move(ipc_key_fd),
                                                                std::move(worker_config), threads, args.shard_index};
    loop.run();

    return 0;
}
