// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/worker_supervisor.hpp"

#include "merovingian/core/file_descriptor.hpp"
#include "merovingian/crypto/ipc_auth_key.hpp"
#include "merovingian/homeserver/worker_env.hpp"
#include "merovingian/observability/logger.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstring>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <spawn.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

namespace merovingian::homeserver
{

namespace
{

    [[nodiscard]] auto make_ipc_socketpair() -> std::pair<core::FileDescriptor, core::FileDescriptor>
    {
        auto fds = std::array<int, 2>{-1, -1};
        if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds.data()) != 0)
        {
            throw std::runtime_error{"socketpair failed: " + std::string{::strerror(errno)}};
        }
        return {core::FileDescriptor{fds[0]}, core::FileDescriptor{fds[1]}};
    }

    // Moves `fd` above every fixed child fd number in `reserved` when it sits
    // on one of them, keeping it close-on-exec. A source already on a
    // posix_spawn_file_actions_adddup2 target would either be clobbered before
    // its own dup2 runs or, if it is that dup2's own target, become a same-fd
    // dup2 — which some libcs treat as a no-op that leaves FD_CLOEXEC set.
    // Relocating past the highest reserved number places it above all of them,
    // since fd allocation is contiguous from the lowest available number.
    [[nodiscard]] auto relocate_off_reserved_fds(core::FileDescriptor fd, std::span<int const> reserved,
                                                 char const* what) -> core::FileDescriptor
    {
        if (std::ranges::none_of(reserved, [&fd](int number) {
                return fd.get() == number;
            }))
        {
            return fd;
        }
        auto const highest_reserved = *std::ranges::max_element(reserved);
        auto const relocated = ::fcntl(fd.get(), F_DUPFD_CLOEXEC, highest_reserved + 1);
        if (relocated < 0)
        {
            throw std::runtime_error{std::string{"ipc: failed to relocate "} + what + ": " + ::strerror(errno)};
        }
        fd.reset(relocated);
        return fd;
    }

    constexpr auto worker_fixed_fds = std::array<int, 3>{kWorkerIpcFd, kWorkerIpcKeyFd, kWorkerDbUriFd};

} // namespace

WorkerSupervisor::WorkerSupervisor(std::string worker_path, std::string config_path,
                                   std::uint32_t request_timeout_seconds, std::uint32_t shard_index,
                                   core::SecretBuffer ipc_auth_key_material, std::uint32_t max_frame_bytes,
                                   core::SecretBuffer worker_database_uri_material)
    : worker_path_{std::move(worker_path)}
    , config_path_{std::move(config_path)}
    , request_timeout_seconds_{request_timeout_seconds}
    , shard_index_{shard_index}
    , ipc_auth_key_material_{std::move(ipc_auth_key_material)}
    , max_frame_bytes_{max_frame_bytes}
    , worker_database_uri_material_{std::move(worker_database_uri_material)}
{
}

WorkerSupervisor::~WorkerSupervisor()
{
    stop();
}

auto make_worker_secret_pipe(std::span<std::uint8_t const> secret, std::span<int const> reserved_fds)
    -> core::FileDescriptor
{
    if (secret.empty())
    {
        throw std::runtime_error{"ipc: refusing to hand the worker empty secret material"};
    }

    // Both ends start O_CLOEXEC and the read end stays that way in this
    // process: main is multithreaded, so clearing FD_CLOEXEC here would let
    // any concurrent spawn (another shard's restart, the thumbnail decoder)
    // inherit the pipe carrying the secret. The child receives it only
    // through the caller's own adddup2 file action onto its fixed fd number.
    auto secret_fds = std::array<int, 2>{-1, -1};
    if (::pipe2(secret_fds.data(), O_CLOEXEC) != 0)
    {
        throw std::runtime_error{"ipc: failed to create worker secret pipe: " + std::string{::strerror(errno)}};
    }
    // Keep the read end off every reserved (fixed child) fd number, or the
    // worker could lose the secret (see relocate_off_reserved_fds).
    auto read_end =
        relocate_off_reserved_fds(core::FileDescriptor{secret_fds[0]}, reserved_fds, "worker secret pipe fd");
    auto write_end = core::FileDescriptor{secret_fds[1]};

    // Auth keys and connection URIs are both far below PIPE_BUF, so this
    // write never blocks on an unread pipe; the loop only covers EINTR and
    // short writes.
    auto written = std::size_t{0U};
    while (written < secret.size())
    {
        auto const write_rc = ::write(write_end.get(), secret.data() + written, secret.size() - written);
        if (write_rc < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            throw std::runtime_error{"ipc: failed to write worker secret: " + std::string{::strerror(errno)}};
        }
        written += static_cast<std::size_t>(write_rc);
    }
    // Closing the only write end lets the worker's read observe EOF right
    // after the secret bytes.
    write_end.reset();
    return read_end;
}

auto make_worker_ipc_socketpair() -> std::pair<core::FileDescriptor, core::FileDescriptor>
{
    auto [server, client] = make_ipc_socketpair();
    // 0.12.13 audit item 8: with stdin closed the pair is fds 0 and 3, and the
    // child's end on kWorkerIpcFd would make its adddup2 a same-fd dup2.
    return {std::move(server), relocate_off_reserved_fds(std::move(client), worker_fixed_fds, "worker IPC socket fd")};
}

auto make_worker_key_pipe(std::span<std::uint8_t const> key) -> core::FileDescriptor
{
    auto const reserved = std::array<int, 2>{kWorkerIpcFd, kWorkerIpcKeyFd};
    return make_worker_secret_pipe(key, reserved);
}

auto make_worker_db_uri_pipe(std::span<std::uint8_t const> uri) -> core::FileDescriptor
{
    auto const reserved = std::array<int, 3>{kWorkerIpcFd, kWorkerIpcKeyFd, kWorkerDbUriFd};
    return make_worker_secret_pipe(uri, reserved);
}

auto WorkerSupervisor::set_request_handler(ipc::IpcChannel::RequestHandler handler) -> void
{
    request_handler_ = std::move(handler);
}

auto WorkerSupervisor::start() -> void
{
    running_.store(true);
    spawn_and_connect();
    supervisor_thread_ = std::thread{[this]() {
        supervisor_loop();
    }};
}

auto WorkerSupervisor::stop() noexcept -> void
{
    if (!running_.exchange(false))
    {
        return;
    }

    // A deliberate shutdown is not a failure, but the supervisor is no longer
    // available to route work, so report unhealthy until it is started again.
    healthy_.store(false);

    // Take ownership of channel_ under the lock and release the lock before
    // calling stop() on it. channel_->stop() joins the dispatch thread, which
    // may be running the pdu_ingest handler; that handler's notify_room_changed()
    // calls channel_snapshot() on this same supervisor when the ingested room
    // hashes to this shard (the common case — see worker_pool.cpp). Holding
    // channel_mu_ across the join would deadlock: this thread waits for the
    // dispatch thread to finish while the dispatch thread waits for this
    // thread to release channel_mu_.
    auto channel = std::shared_ptr<ipc::IpcChannel>{}; // SHARED_PTR: reviewed — ref-counted snapshot keeps IpcChannel
                                                       // alive across concurrent supervisor restarts
    {
        auto lock = std::lock_guard{channel_mu_};
        channel = std::move(channel_);
    }
    if (channel)
    {
        if (channel->healthy())
        {
            try
            {
                channel->send_notification(R"({"type":"shutdown"})");
            }
            catch (...)
            {
            }
        }
        channel->stop();
    }
    if (supervisor_thread_.joinable())
    {
        supervisor_thread_.join();
    }

    // The supervisor thread has already reaped the worker in the common case.
    // If it exited without waiting (e.g. waitpid failure or a restart loop race),
    // reap it here with a bounded wait so a stuck child cannot hang process
    // shutdown or test teardown. TSan-instrumented workers can be very slow to
    // exit, so allow a generous grace period before escalating to SIGTERM and
    // then SIGKILL.
    if (worker_pid_.load() > 0)
    {
        auto const deadline =
            std::chrono::steady_clock::now() + std::chrono::seconds{static_cast<long>(request_timeout_seconds_)};
        auto const wait_step = std::chrono::milliseconds{10};
        auto reaped = false;
        while (std::chrono::steady_clock::now() < deadline)
        {
            auto status = int{0};
            auto const rc = ::waitpid(worker_pid_.load(), &status, WNOHANG);
            if (rc == worker_pid_.load())
            {
                reaped = true;
                break;
            }
            if (rc < 0)
            {
                if (errno != EINTR)
                {
                    if (errno == ECHILD)
                    {
                        // The supervisor thread already reaped the child; no
                        // further escalation is needed.
                        reaped = true;
                    }
                    else
                    {
                        LOG_WARNING("Federation worker waitpid failed during stop: " + std::string{::strerror(errno)});
                    }
                    break;
                }
            }
            std::this_thread::sleep_for(wait_step);
        }

        if (!reaped)
        {
            LOG_WARNING("Federation worker did not exit within " + std::to_string(request_timeout_seconds_) +
                        "s; sending SIGTERM");
            std::ignore = ::kill(worker_pid_.load(), SIGTERM);

            auto const term_deadline =
                std::chrono::steady_clock::now() + std::chrono::seconds{static_cast<long>(request_timeout_seconds_)};
            while (std::chrono::steady_clock::now() < term_deadline)
            {
                auto status = int{0};
                auto const rc = ::waitpid(worker_pid_.load(), &status, WNOHANG);
                if (rc == worker_pid_.load())
                {
                    reaped = true;
                    break;
                }
                if (rc < 0 && errno != EINTR)
                {
                    if (errno == ECHILD)
                    {
                        reaped = true;
                    }
                    break;
                }
                std::this_thread::sleep_for(wait_step);
            }
        }

        if (!reaped)
        {
            LOG_WARNING("Federation worker ignored SIGTERM; sending SIGKILL");
            std::ignore = ::kill(worker_pid_.load(), SIGKILL);
            std::ignore = ::waitpid(worker_pid_.load(), nullptr, 0);
        }

        worker_pid_.store(-1);
    }
}

auto WorkerSupervisor::channel() noexcept -> ipc::IpcChannel&
{
    // Only safe from within the IPC dispatch thread (request handler), where
    // the channel is guaranteed to outlive the call — IpcChannel::stop() joins
    // that thread before the channel is destroyed — so no lock is needed there.
    return *channel_;
}

auto WorkerSupervisor::channel_snapshot() const noexcept
    -> std::shared_ptr<ipc::IpcChannel> // SHARED_PTR: reviewed — ref-counted snapshot keeps IpcChannel alive across
                                        // concurrent supervisor restarts
{
    auto lock = std::lock_guard{channel_mu_};
    return channel_;
}

auto WorkerSupervisor::healthy() const noexcept -> bool
{
    // A supervisor is healthy before start() is called (it has not failed)
    // and, once started, only while its IPC channel is alive.
    // Use channel_snapshot() so this read is safe under concurrent restart.
    auto const ch = channel_snapshot();
    return healthy_.load() && (!ch || ch->healthy());
}

auto WorkerSupervisor::request_timeout() const noexcept -> std::uint32_t
{
    return request_timeout_seconds_;
}

auto WorkerSupervisor::shard_index() const noexcept -> std::uint32_t
{
    return shard_index_;
}

auto WorkerSupervisor::set_max_in_flight(std::size_t cap) noexcept -> void
{
    ipc_max_in_flight_ = cap;
}

auto WorkerSupervisor::set_dispatch_queue_limits(std::size_t max_count, std::uint64_t max_bytes) noexcept -> void
{
    ipc_max_dispatch_queue_count_ = max_count;
    ipc_max_dispatch_queue_bytes_ = max_bytes;
}

auto WorkerSupervisor::worker_pid() const noexcept -> pid_t
{
    return worker_pid_.load();
}

auto WorkerSupervisor::spawn_and_connect() -> void
{
    // Build the IpcAuthKey value for this process's side of the channel from
    // the material the caller (WorkerPool) already derived from the operator
    // master-key file once — this supervisor never opens that file itself,
    // on the initial spawn or any restart. Fail closed before spawning
    // anything: an unauthenticated handshake would let any peer inject AEAD
    // frames, and a worker started without usable key material would only
    // fail right back on its own key-fd read anyway. See ADR-0062.
    auto const auth_key = crypto::ipc_auth_key_from_bytes(ipc_auth_key_material_.bytes());
    if (!auth_key.has_value())
    {
        throw std::runtime_error{
            "ipc: worker IPC auth key material is missing or the wrong size; cannot authenticate worker IPC channel"};
    }

    auto [server_fd, client_fd] = make_worker_ipc_socketpair();

    // Hand the already-derived auth key to the worker over a second inherited
    // fd (finding N1): the worker must never open the master key file itself,
    // so it receives only these 32 derived bytes, never the root secret they
    // came from. The read end stays FD_CLOEXEC here; the adddup2 file action
    // below makes it inheritable in the child alone (ADR-0062).
    auto key_read_fd = make_worker_key_pipe(ipc_auth_key_material_.bytes());
    auto const ipc_key_fd_str = std::to_string(kWorkerIpcKeyFd);

    // ADR-0062 part 2: hand the worker a separate, least-privilege database
    // connection URI the same way, over a third inherited pipe — but only
    // when the caller (WorkerPool) actually derived one. Empty
    // worker_database_uri_material_ means database.backend=sqlite (no role
    // to separate) or federation.worker.allow_shared_database_credentials=true
    // (the worker shares main's credentials instead); in either case no
    // --db-uri-fd is passed and the worker keeps its own copy of
    // database.uri_file/runtime_role/migration_role untouched.
    auto const has_db_uri = !worker_database_uri_material_.bytes().empty();
    auto db_uri_read_fd =
        has_db_uri ? make_worker_db_uri_pipe(worker_database_uri_material_.bytes()) : core::FileDescriptor{};
    auto const db_uri_fd_str = std::to_string(kWorkerDbUriFd);

    auto const ipc_fd_str = std::to_string(kWorkerIpcFd);
    auto const shard_index_str = std::to_string(shard_index_);

    auto argv = std::vector<char const*>{
        worker_path_.c_str(),   "--config", config_path_.c_str(),    "--ipc-fd", ipc_fd_str.c_str(), "--ipc-key-fd",
        ipc_key_fd_str.c_str(), "--shard",  shard_index_str.c_str(),
    };
    if (has_db_uri)
    {
        argv.push_back("--db-uri-fd");
        argv.push_back(db_uri_fd_str.c_str());
    }
    argv.push_back(nullptr);

    posix_spawn_file_actions_t file_actions{};
    ::posix_spawn_file_actions_init(&file_actions);
    // Close the server-side fd in the child first.  The socketpair may have
    // returned server_fd == kWorkerIpcFd; if we dup client_fd onto that fd
    // before closing server_fd, the subsequent close would drop the IPC fd.
    ::posix_spawn_file_actions_addclose(&file_actions, server_fd.get());
    // Place client_fd at the fixed kWorkerIpcFd in the child.
    ::posix_spawn_file_actions_adddup2(&file_actions, client_fd.get(), kWorkerIpcFd);
    // Place the key pipe at kWorkerIpcKeyFd. dup2 clears FD_CLOEXEC on the
    // child's copy only; make_worker_key_pipe guarantees the source is neither
    // fixed fd, so this cannot be a same-fd dup2 or be clobbered by the one above.
    ::posix_spawn_file_actions_adddup2(&file_actions, key_read_fd.get(), kWorkerIpcKeyFd);
    if (has_db_uri)
    {
        // Same guarantee as above, extended to the third fixed fd:
        // make_worker_db_uri_pipe keeps its source off all three reserved
        // numbers, so this dup2 cannot collide with either of the other two.
        ::posix_spawn_file_actions_adddup2(&file_actions, db_uri_read_fd.get(), kWorkerDbUriFd);
    }

    // Minimal allowlist environment: PATH only (issue #330). The strings and
    // pointer array live for the duration of the posix_spawn call below.
    auto const worker_env = homeserver::build_minimal_worker_env();

    pid_t pid{-1};
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast) — posix_spawn argv/envp are char* const*
    auto const rc =
        ::posix_spawn(&pid, worker_path_.c_str(), &file_actions, nullptr, const_cast<char* const*>(argv.data()),
                      const_cast<char* const*>(worker_env.argv.data()));
    ::posix_spawn_file_actions_destroy(&file_actions);

    if (rc != 0)
    {
        throw std::runtime_error{"posix_spawn(" + worker_path_ + "): " + std::string{::strerror(rc)}};
    }

    client_fd.reset();
    key_read_fd.reset();    // the child inherited its own copy; this one is no longer needed
    db_uri_read_fd.reset(); // ditto, when a db-uri pipe was created
    worker_pid_.store(pid);

    auto new_channel = std::make_shared<ipc::IpcChannel>(std::move(server_fd), ipc::IpcChannel::Role::server, *auth_key,
                                                         max_frame_bytes_);
    new_channel->set_max_in_flight(ipc_max_in_flight_);
    new_channel->set_dispatch_queue_limits(ipc_max_dispatch_queue_count_, ipc_max_dispatch_queue_bytes_);
    if (request_handler_)
    {
        new_channel->set_request_handler(request_handler_);
    }
    new_channel->start();

    {
        auto lock = std::lock_guard{channel_mu_};
        channel_ = std::move(new_channel);
    }

    LOG_INFO("Federation worker spawned: shard=" + std::to_string(shard_index_) + " pid=" + std::to_string(pid) +
             " binary=" + worker_path_);
}

auto WorkerSupervisor::supervisor_loop() -> void
{
    auto backoff_ms = std::uint32_t{1000U};
    constexpr auto kMaxBackoffMs = std::uint32_t{30000U};
    constexpr auto stable_uptime = std::chrono::seconds{30};
    auto healthy_since = std::optional<std::chrono::steady_clock::time_point>{};

    while (running_.load())
    {
        auto const pid = worker_pid_.load();
        if (pid > 0)
        {
            auto status = int{0};
            auto const waited = ::waitpid(pid, &status, WNOHANG);
            if (waited == 0)
            {
                auto const now = std::chrono::steady_clock::now();
                if (healthy())
                {
                    if (!healthy_since.has_value())
                    {
                        healthy_since = now;
                    }
                    if (now - *healthy_since >= stable_uptime)
                    {
                        backoff_ms = 1000U;
                    }
                }
                else
                {
                    healthy_since.reset();
                }
                std::this_thread::sleep_for(std::chrono::milliseconds{100});
                continue;
            }
            if (waited < 0)
            {
                if (errno == EINTR)
                {
                    continue;
                }
                if (errno != ECHILD)
                {
                    healthy_.store(false);
                    LOG_WARNING("Federation worker waitpid failed: " + std::string{::strerror(errno)});
                    break; // Preserve the owned PID for stop() to reap.
                }
            }
            if (!running_.load())
            {
                break;
            }
            auto const exit_code = waited > 0 && WIFEXITED(status) ? WEXITSTATUS(status) : -1;
            LOG_WARNING("Federation worker exited: pid=" + std::to_string(pid) +
                        " exit_code=" + std::to_string(exit_code) + " restart_in_ms=" + std::to_string(backoff_ms));
            worker_pid_.store(-1);
        }

        // Mark unhealthy and take ownership of channel_ under the mutex so
        // WorkerPool::handle() can never dereference a channel_ that is being
        // destroyed concurrently. As in stop(), channel_->stop() must run
        // without channel_mu_ held: it joins the dispatch thread, and a
        // pdu_ingest handler running there can call back into this same
        // supervisor's channel_snapshot() (via notify_room_changed()) and
        // deadlock against this thread holding the lock.
        healthy_.store(false);
        healthy_since.reset();
        auto old_channel = std::shared_ptr<ipc::IpcChannel>{}; // SHARED_PTR: reviewed — ref-counted snapshot keeps
                                                               // IpcChannel alive across concurrent supervisor restarts
        {
            auto lock = std::lock_guard{channel_mu_};
            old_channel = std::move(channel_);
        }
        if (old_channel)
        {
            old_channel->stop();
        }
        // A failed spawn leaves no owned child. Never waitpid(-1): that can
        // reap another shard, or turn ECHILD into permanent loss of supervision.
        // Sleep in bounded steps so shutdown can interrupt even maximum backoff.
        auto const deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds{backoff_ms};
        while (running_.load() && std::chrono::steady_clock::now() < deadline)
        {
            std::this_thread::sleep_for(std::min(std::chrono::steady_clock::duration{std::chrono::milliseconds{100}},
                                                 deadline - std::chrono::steady_clock::now()));
        }
        backoff_ms = std::min(backoff_ms * 2U, kMaxBackoffMs);

        if (!running_.load())
        {
            break;
        }

        try
        {
            spawn_and_connect();
            // A successful spawn is not evidence of stability. Reset backoff
            // only after the child and its IPC channel stay healthy for 30s.
            // Restart succeeded — restore the healthy flag so the pool
            // routes new requests to this worker again.
            healthy_.store(true);
        }
        catch (std::exception const& ex)
        {
            LOG_WARNING("Federation worker restart failed: " + std::string{ex.what()});
        }
    }
}

} // namespace merovingian::homeserver
