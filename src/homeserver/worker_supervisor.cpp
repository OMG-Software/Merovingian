// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/worker_supervisor.hpp"

#include "merovingian/core/file_descriptor.hpp"
#include "merovingian/observability/logger.hpp"

#include <array>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>

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
                                   std::uint32_t request_timeout_seconds, std::uint32_t shard_index)
    : worker_path_{std::move(worker_path)}
    , config_path_{std::move(config_path)}
    , request_timeout_seconds_{request_timeout_seconds}
    , shard_index_{shard_index}
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
    {
        auto lock = std::lock_guard{channel_mu_};
        if (channel_ && channel_->healthy())
        {
            try
            {
                channel_->send_notification(R"({"type":"shutdown"})");
            }
            catch (...)
            {
            }
        }
        if (channel_)
        {
            channel_->stop();
            channel_.reset();
        }
    }
    if (supervisor_thread_.joinable())
    {
        supervisor_thread_.join();
    }
    if (worker_pid_ > 0)
    {
        ::waitpid(worker_pid_, nullptr, 0);
        worker_pid_ = -1;
    }
}

auto WorkerSupervisor::channel() noexcept -> ipc::IpcChannel&
{
    // Only safe from within the IPC reader thread (request handler), where the
    // channel is guaranteed to outlive the call — no lock needed there.
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
    return healthy_.load() && (!channel_ || channel_->healthy());
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

    pid_t pid{-1};
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast) — posix_spawn argv is char* const*
    auto const rc =
        ::posix_spawn(&pid, worker_path_.c_str(), &file_actions, nullptr, const_cast<char* const*>(argv), nullptr);
    ::posix_spawn_file_actions_destroy(&file_actions);

    if (rc != 0)
    {
        throw std::runtime_error{"posix_spawn(" + worker_path_ + "): " + std::string{::strerror(rc)}};
    }

    client_fd.reset();
    worker_pid_ = pid;

    auto new_channel = std::make_shared<ipc::IpcChannel>(std::move(server_fd), ipc::IpcChannel::Role::server);
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

        // Mark unhealthy and reset channel_ under the mutex so WorkerPool::handle()
        // can never dereference a channel_ that is being destroyed concurrently.
        healthy_.store(false);
        {
            auto lock = std::lock_guard{channel_mu_};
            if (channel_)
            {
                channel_->stop();
                channel_.reset();
            }
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
