// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/worker_supervisor.hpp"

#include "merovingian/core/file_descriptor.hpp"
#include "merovingian/crypto/ipc_auth_key.hpp"
#include "merovingian/homeserver/worker_env.hpp"
#include "merovingian/observability/logger.hpp"

#include <array>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstring>
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

} // namespace

WorkerSupervisor::WorkerSupervisor(std::string worker_path, std::string config_path,
                                   std::uint32_t request_timeout_seconds, std::uint32_t shard_index,
                                   core::SecretBuffer ipc_auth_key_material, std::uint32_t max_frame_bytes)
    : worker_path_{std::move(worker_path)}
    , config_path_{std::move(config_path)}
    , request_timeout_seconds_{request_timeout_seconds}
    , shard_index_{shard_index}
    , ipc_auth_key_material_{std::move(ipc_auth_key_material)}
    , max_frame_bytes_{max_frame_bytes}
{
}

WorkerSupervisor::~WorkerSupervisor()
{
    stop();
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

    auto [server_fd, client_fd] = make_ipc_socketpair();

    // Hand the already-derived auth key to the worker over a second inherited
    // fd (finding N1): the worker must never open the master key file itself,
    // so it receives only these 32 derived bytes, never the root secret they
    // came from. Both pipe ends start O_CLOEXEC so a concurrent fork/exec
    // elsewhere in this multithreaded process can never leak either one.
    auto key_fds = std::array<int, 2>{-1, -1};
    if (::pipe2(key_fds.data(), O_CLOEXEC) != 0)
    {
        throw std::runtime_error{"ipc: failed to create worker key pipe: " + std::string{::strerror(errno)}};
    }
    auto key_read_fd = core::FileDescriptor{key_fds[0]};
    auto key_write_fd = core::FileDescriptor{key_fds[1]};

    // pipe2() could in principle hand back kWorkerIpcFd for the read end
    // (e.g. once a prior worker's fds have been closed, freeing low
    // numbers). If it does, relocate it before anything below depends on its
    // number: the dup2-to-kWorkerIpcFd file action for the ipc socket further
    // down would otherwise silently replace this fd in the child's table
    // before exec, the same hazard the addclose(server_fd) below defends
    // against for the ipc socket's own fd.
    if (key_read_fd.get() == kWorkerIpcFd)
    {
        auto const relocated = ::fcntl(key_read_fd.get(), F_DUPFD_CLOEXEC, kWorkerIpcFd + 1);
        if (relocated < 0)
        {
            throw std::runtime_error{"ipc: failed to relocate worker key pipe fd: " + std::string{::strerror(errno)}};
        }
        key_read_fd.reset(relocated);
    }

    {
        auto const key_bytes = ipc_auth_key_material_.bytes();
        auto written = std::size_t{0U};
        while (written < key_bytes.size())
        {
            auto const write_rc = ::write(key_write_fd.get(), key_bytes.data() + written, key_bytes.size() - written);
            if (write_rc < 0)
            {
                if (errno == EINTR)
                {
                    continue;
                }
                throw std::runtime_error{"ipc: failed to write worker IPC auth key: " + std::string{::strerror(errno)}};
            }
            written += static_cast<std::size_t>(write_rc);
        }
    }
    // Close the write end in the parent: the worker only ever reads from this
    // pipe, and closing our only write reference lets the worker's own read
    // observe EOF immediately after the key bytes once its inherited copy of
    // the write end (O_CLOEXEC, so it never survives the worker's own exec)
    // is gone too.
    key_write_fd.reset();

    // Make only the read end inheritable across the upcoming exec, at
    // whatever fd number it already has; every other fd in this process —
    // including the write end just closed above — stays non-inheritable.
    auto const key_read_flags = ::fcntl(key_read_fd.get(), F_GETFD);
    if (key_read_flags < 0 || ::fcntl(key_read_fd.get(), F_SETFD, key_read_flags & ~FD_CLOEXEC) != 0)
    {
        throw std::runtime_error{"ipc: failed to make worker key pipe inheritable: " + std::string{::strerror(errno)}};
    }
    auto const ipc_key_fd_str = std::to_string(key_read_fd.get());

    auto const ipc_fd_str = std::to_string(kWorkerIpcFd);
    auto const shard_index_str = std::to_string(shard_index_);
    auto const* worker_argv0 = worker_path_.c_str();
    // NOLINTNEXTLINE(*-avoid-c-arrays) — posix_spawn requires char* const[]
    char const* argv[] = {
        worker_argv0,           "--config", config_path_.c_str(),    "--ipc-fd", ipc_fd_str.c_str(), "--ipc-key-fd",
        ipc_key_fd_str.c_str(), "--shard",  shard_index_str.c_str(), nullptr,
    };

    posix_spawn_file_actions_t file_actions{};
    ::posix_spawn_file_actions_init(&file_actions);
    // Close the server-side fd in the child first.  The socketpair may have
    // returned server_fd == kWorkerIpcFd; if we dup client_fd onto that fd
    // before closing server_fd, the subsequent close would drop the IPC fd.
    ::posix_spawn_file_actions_addclose(&file_actions, server_fd.get());
    // Place client_fd at the fixed kWorkerIpcFd in the child.
    ::posix_spawn_file_actions_adddup2(&file_actions, client_fd.get(), kWorkerIpcFd);

    // Minimal allowlist environment: PATH only (issue #330). The strings and
    // pointer array live for the duration of the posix_spawn call below.
    auto const worker_env = homeserver::build_minimal_worker_env();

    pid_t pid{-1};
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast) — posix_spawn argv/envp are char* const*
    auto const rc = ::posix_spawn(&pid, worker_path_.c_str(), &file_actions, nullptr, const_cast<char* const*>(argv),
                                  const_cast<char* const*>(worker_env.argv.data()));
    ::posix_spawn_file_actions_destroy(&file_actions);

    if (rc != 0)
    {
        throw std::runtime_error{"posix_spawn(" + worker_path_ + "): " + std::string{::strerror(rc)}};
    }

    client_fd.reset();
    key_read_fd.reset(); // the child inherited its own copy; this one is no longer needed
    worker_pid_.store(pid);

    auto new_channel = std::make_shared<ipc::IpcChannel>(std::move(server_fd), ipc::IpcChannel::Role::server, *auth_key,
                                                         max_frame_bytes_);
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

    while (running_.load())
    {
        auto status = int{0};
        auto const waited = ::waitpid(worker_pid_.load(), &status, WNOHANG);

        if (waited == 0)
        {
            // Child is still running; poll again so a concurrent stop() can
            // exit this loop promptly instead of blocking forever in waitpid().
            std::this_thread::sleep_for(std::chrono::milliseconds{100});
            continue;
        }

        if (waited < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            if (errno == ECHILD)
            {
                // The child has already been reaped (e.g. by stop()); nothing
                // more for this supervisor to do.
                worker_pid_.store(-1);
                break;
            }
            healthy_.store(false);
            LOG_WARNING("Federation worker waitpid failed: " + std::string{::strerror(errno)});
            break;
        }

        // waited == worker_pid_: the child exited.
        if (!running_.load())
        {
            break;
        }

        auto const exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        LOG_WARNING("Federation worker exited: pid=" + std::to_string(worker_pid_.load()) +
                    " exit_code=" + std::to_string(exit_code) + " restart_in_ms=" + std::to_string(backoff_ms));

        // Mark unhealthy and take ownership of channel_ under the mutex so
        // WorkerPool::handle() can never dereference a channel_ that is being
        // destroyed concurrently. As in stop(), channel_->stop() must run
        // without channel_mu_ held: it joins the dispatch thread, and a
        // pdu_ingest handler running there can call back into this same
        // supervisor's channel_snapshot() (via notify_room_changed()) and
        // deadlock against this thread holding the lock.
        healthy_.store(false);
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
        worker_pid_.store(-1);

        std::this_thread::sleep_for(std::chrono::milliseconds{backoff_ms});
        backoff_ms = std::min(backoff_ms * 2U, kMaxBackoffMs);

        if (!running_.load())
        {
            break;
        }

        try
        {
            spawn_and_connect();
            backoff_ms = 1000U;
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
