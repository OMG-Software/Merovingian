// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/worker_supervisor.hpp"

#include "merovingian/core/file_descriptor.hpp"
#include "merovingian/crypto/ipc_auth_key.hpp"
#include "merovingian/crypto/master_key.hpp"
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
                                   std::string master_key_file, std::uint32_t max_frame_bytes)
    : worker_path_{std::move(worker_path)}
    , config_path_{std::move(config_path)}
    , request_timeout_seconds_{request_timeout_seconds}
    , shard_index_{shard_index}
    , master_key_file_{std::move(master_key_file)}
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
    if (worker_pid_ > 0)
    {
        auto const deadline =
            std::chrono::steady_clock::now() + std::chrono::seconds{static_cast<long>(request_timeout_seconds_)};
        auto const wait_step = std::chrono::milliseconds{10};
        auto reaped = false;
        while (std::chrono::steady_clock::now() < deadline)
        {
            auto status = int{0};
            auto const rc = ::waitpid(worker_pid_, &status, WNOHANG);
            if (rc == worker_pid_)
            {
                reaped = true;
                break;
            }
            if (rc < 0)
            {
                if (errno != EINTR)
                {
                    LOG_WARNING("Federation worker waitpid failed during stop: " + std::string{::strerror(errno)});
                    break;
                }
            }
            std::this_thread::sleep_for(wait_step);
        }

        if (!reaped)
        {
            LOG_WARNING("Federation worker did not exit within " + std::to_string(request_timeout_seconds_) +
                        "s; sending SIGTERM");
            std::ignore = ::kill(worker_pid_, SIGTERM);

            auto const term_deadline =
                std::chrono::steady_clock::now() + std::chrono::seconds{static_cast<long>(request_timeout_seconds_)};
            while (std::chrono::steady_clock::now() < term_deadline)
            {
                auto status = int{0};
                auto const rc = ::waitpid(worker_pid_, &status, WNOHANG);
                if (rc == worker_pid_)
                {
                    reaped = true;
                    break;
                }
                if (rc < 0 && errno != EINTR)
                {
                    break;
                }
                std::this_thread::sleep_for(wait_step);
            }
        }

        if (!reaped)
        {
            LOG_WARNING("Federation worker ignored SIGTERM; sending SIGKILL");
            std::ignore = ::kill(worker_pid_, SIGKILL);
            std::ignore = ::waitpid(worker_pid_, nullptr, 0);
        }

        worker_pid_ = -1;
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

auto WorkerSupervisor::spawn_and_connect() -> void
{
    auto [server_fd, client_fd] = make_ipc_socketpair();

    auto const ipc_fd_str = std::to_string(kWorkerIpcFd);
    auto const shard_index_str = std::to_string(shard_index_);
    auto const* worker_argv0 = worker_path_.c_str();
    // NOLINTNEXTLINE(*-avoid-c-arrays) — posix_spawn requires char* const[]
    char const* argv[] = {
        worker_argv0,       "--config", config_path_.c_str(),    "--ipc-fd",
        ipc_fd_str.c_str(), "--shard",  shard_index_str.c_str(), nullptr,
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
    worker_pid_ = pid;

    // Derive the IPC auth key from the operator master-key file. Both this
    // process and the worker read the same file and derive the same key, so
    // the worker can authenticate the handshake without the key ever crossing
    // the IPC boundary. Fail closed if the master key is unavailable: an
    // unauthenticated handshake would let any peer inject AEAD frames.
    auto const master_material = crypto::load_master_key_material(master_key_file_);
    if (!master_material.has_value())
    {
        throw std::runtime_error{"ipc: master key file '" + master_key_file_ +
                                 "' is unavailable; cannot authenticate worker IPC channel"};
    }
    auto const auth_key = crypto::derive_ipc_auth_key(*master_material);
    if (!auth_key.has_value())
    {
        throw std::runtime_error{"ipc: failed to derive worker IPC auth key from master key file"};
    }

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
        auto const waited = ::waitpid(worker_pid_, &status, 0);

        if (!running_.load())
        {
            break;
        }
        if (waited < 0)
        {
            healthy_.store(false);
            LOG_WARNING("Federation worker waitpid failed: " + std::string{::strerror(errno)});
            break;
        }

        auto const exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        LOG_WARNING("Federation worker exited: pid=" + std::to_string(worker_pid_) +
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
        worker_pid_ = -1;

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
