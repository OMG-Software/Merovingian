// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/ipc/channel.hpp"

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

namespace merovingian::homeserver
{

// Spawns and monitors the merovingian-fed-worker child process.
//
// The child process is launched with a socketpair fd for IPC. The
// supervisor monitors the child via waitpid and restarts it with
// exponential back-off (1s/2s/4s/8s/30s cap) on unexpected exit.
//
// Thread safety:
//   start() may be called once.
//   channel() is safe from within the IPC reader thread (the request handler).
//   channel_snapshot() is safe from any external thread; it returns a
//     shared_ptr that keeps the channel alive across concurrent restarts.
//   stop() is safe to call from any thread.
class WorkerSupervisor final
{
public:
    // worker_path: absolute path to merovingian-fed-worker executable.
    // config_path: path passed as --config to the worker.
    // request_timeout: per-request IPC timeout forwarded to channel usage.
    // shard_index: index of this worker (0..shards-1); passed to the worker
    // as --shard so it can include the index in log output.
    WorkerSupervisor(std::string worker_path, std::string config_path, std::uint32_t request_timeout_seconds,
                     std::uint32_t shard_index = 0U);
    ~WorkerSupervisor();

    WorkerSupervisor(WorkerSupervisor const&) = delete;
    auto operator=(WorkerSupervisor const&) -> WorkerSupervisor& = delete;
    WorkerSupervisor(WorkerSupervisor&&) = delete;
    auto operator=(WorkerSupervisor&&) -> WorkerSupervisor& = delete;

    // Sets the request handler called for inbound messages from the worker
    // (e.g. pdu_ingest). Must be called before start().
    auto set_request_handler(ipc::IpcChannel::RequestHandler handler) -> void;

    // Spawns the worker process, performs the IPC handshake, and starts the
    // reader thread and supervisor monitor thread. Throws on failure.
    auto start() -> void;

    // Signals shutdown: sends a shutdown notification to the worker, closes
    // the IPC channel, and joins all background threads.
    auto stop() noexcept -> void;

    // Returns a reference to the current channel. Only safe to call from
    // within the IPC reader thread (the request handler callback), where the
    // channel is guaranteed to outlive the call.
    [[nodiscard]] auto channel() noexcept -> ipc::IpcChannel&;

    // Returns a shared_ptr snapshot of the current channel. Safe to call from
    // any thread; the returned pointer keeps the channel alive even if a
    // concurrent restart replaces channel_ before the caller finishes.
    // Returns nullptr if no channel is active.
    [[nodiscard]] auto channel_snapshot() const noexcept -> std::shared_ptr<ipc::IpcChannel>;

    [[nodiscard]] auto healthy() const noexcept -> bool;
    [[nodiscard]] auto request_timeout() const noexcept -> std::uint32_t;
    [[nodiscard]] auto shard_index() const noexcept -> std::uint32_t;

private:
    auto spawn_and_connect() -> void;
    auto supervisor_loop() -> void;

    std::string worker_path_;
    std::string config_path_;
    std::uint32_t request_timeout_seconds_{};
    std::uint32_t shard_index_{};
    ipc::IpcChannel::RequestHandler request_handler_{};

    // channel_ and channel_mu_ guard the IpcChannel pointer against concurrent
    // reads (WorkerPool::handle) and writes (supervisor_loop restart, stop).
    mutable std::mutex channel_mu_{};
    std::shared_ptr<ipc::IpcChannel> channel_{};
    pid_t worker_pid_{-1};

    std::thread supervisor_thread_{};
    std::atomic<bool> running_{false};
    std::atomic<bool> healthy_{true};
};

// Fixed fd number used for the IPC socket in the worker child process.
// posix_spawn_file_actions_adddup2 places the socketpair end here.
inline constexpr int kWorkerIpcFd{3};

} // namespace merovingian::homeserver
