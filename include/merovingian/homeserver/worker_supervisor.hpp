// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/core/file_descriptor.hpp"
#include "merovingian/core/secret_buffer.hpp"
#include "merovingian/ipc/channel.hpp"

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <thread>
#include <utility>

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
    // ipc_auth_key_material: the IPC channel auth key, already derived from the
    // operator master-key file by the caller (WorkerPool, once, for every
    // shard) — see crypto::derive_ipc_auth_key. The worker never opens the
    // master key file itself: each spawn (and every restart) writes exactly
    // these bytes into a pipe inherited by the child, which reads them back
    // and rebuilds the same key via crypto::ipc_auth_key_from_bytes (see
    // federation_worker::read_ipc_auth_key). If empty or the wrong size the
    // supervisor refuses to spawn (fail-closed), because an unauthenticated
    // IPC handshake would let any peer inject frames. See ADR-0062.
    // max_frame_bytes: IpcChannel frame cap for this channel; 0 means "use
    // ipc::kIpcMaxFrameBytes". The worker computes the same value from its own
    // copy of the config, so both sides of the channel must agree — see
    // ipc::frame_bytes_for_response_cap.
    // worker_database_uri_material: ADR-0062 part 2. When non-empty, the
    // already-read bytes of a PostgreSQL connection URI for a separate,
    // least-privilege worker login (see homeserver::WorkerPool::WorkerPool),
    // handed to the worker the same way as ipc_auth_key_material — a second
    // pipe inherited at spawn, never a file the worker opens. Empty means no
    // separate URI is delivered: either database.backend=sqlite (no role to
    // separate) or federation.worker.allow_shared_database_credentials=true
    // (the worker shares main's credentials, today's pre-part-2 behaviour).
    WorkerSupervisor(std::string worker_path, std::string config_path, std::uint32_t request_timeout_seconds,
                     std::uint32_t shard_index = 0U, core::SecretBuffer ipc_auth_key_material = {},
                     std::uint32_t max_frame_bytes = 0U, core::SecretBuffer worker_database_uri_material = {});
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
    [[nodiscard]] auto channel_snapshot() const noexcept
        -> std::shared_ptr<ipc::IpcChannel>; // SHARED_PTR: reviewed — ref-counted snapshot prevents use-after-free when
                                             // supervisor restarts and resets channel_ concurrently

    // Configures the per-channel in-flight cap enforced by main against a
    // flooded federation worker (0.12.13 audit, finding H2). The cap applies
    // to every request type on this channel; requests over the cap receive an
    // explicit overload reply instead of being queued. May be called before
    // start() and is reapplied on every worker restart.
    auto set_max_in_flight(std::size_t cap) noexcept -> void;

    [[nodiscard]] auto healthy() const noexcept -> bool;
    [[nodiscard]] auto request_timeout() const noexcept -> std::uint32_t;
    [[nodiscard]] auto shard_index() const noexcept -> std::uint32_t;
    // The PID of the currently supervised worker process, or -1 if no child
    // is running. Exposed primarily for integration tests that need to signal the
    // worker (e.g. to verify restart/backoff behaviour), but also useful for
    // external diagnostics.
    [[nodiscard]] auto worker_pid() const noexcept -> pid_t;

private:
    auto spawn_and_connect() -> void;
    auto supervisor_loop() -> void;

    std::string worker_path_;
    std::string config_path_;
    std::uint32_t request_timeout_seconds_{};
    std::uint32_t shard_index_{};
    core::SecretBuffer ipc_auth_key_material_{};
    std::uint32_t max_frame_bytes_{};
    std::size_t ipc_max_in_flight_{0U};
    core::SecretBuffer worker_database_uri_material_{};
    ipc::IpcChannel::RequestHandler request_handler_{};

    // channel_ and channel_mu_ guard the IpcChannel pointer against concurrent
    // reads (WorkerPool::handle) and writes (supervisor_loop restart, stop).
    mutable std::mutex channel_mu_{};
    std::shared_ptr<ipc::IpcChannel> channel_{}; // SHARED_PTR: reviewed — shared ownership with channel_snapshot()
                                                 // callers prevents use-after-free on restart
    std::atomic<pid_t> worker_pid_{-1};

    std::thread supervisor_thread_{};
    std::atomic<bool> running_{false};
    std::atomic<bool> healthy_{true};
};

// Fixed fd number used for the IPC socket in the worker child process.
// posix_spawn_file_actions_adddup2 places the socketpair end here.
inline constexpr int kWorkerIpcFd{3};

// Fixed fd number the worker key pipe occupies in the worker child process
// (ADR-0062). Like kWorkerIpcFd it is placed by
// posix_spawn_file_actions_adddup2, which clears FD_CLOEXEC in the child only.
inline constexpr int kWorkerIpcKeyFd{4};

// Fixed fd number the worker's separate database-URI pipe occupies in the
// child process, when one is delivered (ADR-0062 part 2). Placed the same
// way as kWorkerIpcFd and kWorkerIpcKeyFd.
inline constexpr int kWorkerDbUriFd{5};

// Generalized form of the pipe-based secret handoff both make_worker_key_pipe
// and make_worker_db_uri_pipe use: writes `secret`, closes the write end, and
// returns the read end. The read end stays FD_CLOEXEC in this (multithreaded)
// process, so no concurrent spawn can inherit it — clearing it here would let
// another shard's restart or the thumbnail decoder inherit a live secret
// pipe. It also never lands on any fd number in `reserved_fds` (relocated via
// F_DUPFD_CLOEXEC past the highest one), so a posix_spawn_file_actions_adddup2
// placing another secret onto one of those fixed numbers can neither clobber
// this fd nor degenerate into a same-fd dup2 (which some libcs treat as a
// no-op that leaves FD_CLOEXEC set). Throws std::runtime_error on failure,
// including on empty `secret`.
[[nodiscard]] auto make_worker_secret_pipe(std::span<std::uint8_t const> secret, std::span<int const> reserved_fds)
    -> core::FileDescriptor;

// Creates the AF_UNIX socket pair for a worker's IPC channel: {server end for
// main, client end for the child}. Both are close-on-exec in this process,
// and the client end never occupies a fixed child fd number (kWorkerIpcFd,
// kWorkerIpcKeyFd, kWorkerDbUriFd): posix_spawn_file_actions_adddup2 onto
// kWorkerIpcFd from a source already numbered kWorkerIpcFd is a same-fd dup2,
// which some libcs treat as a no-op that leaves FD_CLOEXEC set, so the worker
// would start without its IPC socket. That happens when main runs with its
// stdin closed: socketpair then returns fds 0 and 3.
[[nodiscard]] auto make_worker_ipc_socketpair() -> std::pair<core::FileDescriptor, core::FileDescriptor>;

// Creates the pipe that hands the worker its IPC auth key — see
// make_worker_secret_pipe. Reserves kWorkerIpcFd and kWorkerIpcKeyFd.
[[nodiscard]] auto make_worker_key_pipe(std::span<std::uint8_t const> key) -> core::FileDescriptor;

// Creates the pipe that hands the worker its separate database connection
// URI (ADR-0062 part 2) — see make_worker_secret_pipe. Reserves kWorkerIpcFd,
// kWorkerIpcKeyFd, and kWorkerDbUriFd.
[[nodiscard]] auto make_worker_db_uri_pipe(std::span<std::uint8_t const> uri) -> core::FileDescriptor;

} // namespace merovingian::homeserver
