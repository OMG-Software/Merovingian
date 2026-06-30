// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/config/config_parser.hpp"
#include "merovingian/core/file_descriptor.hpp"
#include "merovingian/federation_worker/args.hpp"
#include "merovingian/observability/logger.hpp"
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
             " ipc_fd=" + std::to_string(raw_fd));

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
    auto const threads = parse_result.config.federation_worker().threads;

    // Apply the worker-specific runtime hardening sequence (issue #319): core
    // dump policy, PR_SET_NO_NEW_PRIVS, capability-bounding drop, then the
    // worker seccomp-bpf filter (which denies execve/execveat — the worker never
    // spawns). Done after config + master-key file are read and the IPC fd is
    // validated, but before the event loop opens the DB and starts threads. The
    // worker filter still allows open()/socket()/clone() etc, so startup is not
    // blocked. Fail-closed: a failed control aborts the worker. The
    // apply_hardening config flag lets tests run the worker unfiltered while the
    // allowlist itself is validated in unit tests.
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

    auto loop = merovingian::federation_worker::WorkerEventLoop{std::move(ipc_fd), parse_result.config, threads,
                                                                args.shard_index};
    loop.run();

    return 0;
}
