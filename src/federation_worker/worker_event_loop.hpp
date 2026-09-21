// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/config/config.hpp"
#include "merovingian/core/file_descriptor.hpp"

namespace merovingian::federation_worker
{

// Owns the IpcChannel, thread pool, and HomeserverRuntime for the
// out-of-process federation worker process. The worker handles inbound
// federation HTTP requests forwarded from the main process and calls
// pdu_ingest back on main via IPC for each accepted PDU.
class WorkerEventLoop final
{
public:
    // ipc_key_fd: the read end of the pipe main writes the IPC auth key into
    // at spawn time (see homeserver::WorkerSupervisor::spawn_and_connect and
    // federation_worker::read_ipc_auth_key). run() reads exactly the key from
    // it and never opens the operator master-key file itself — see ADR-0062.
    // db_uri_fd: ADR-0062 part 2. The read end of the pipe main writes a
    // separate, least-privilege database connection URI into, when one
    // applies (database.backend=postgresql and no
    // allow_shared_database_credentials opt-out). An invalid (default
    // FileDescriptor{}) value means no separate URI was delivered: run()
    // then leaves the worker's own copy of database.uri_file/runtime_role/
    // migration_role untouched, so it opens the database exactly as main
    // does.
    WorkerEventLoop(core::FileDescriptor ipc_fd, core::FileDescriptor ipc_key_fd, core::FileDescriptor db_uri_fd,
                    config::Config config, std::uint32_t threads, std::uint32_t shard_index = 0U);
    ~WorkerEventLoop() = default;

    WorkerEventLoop(WorkerEventLoop const&) = delete;
    auto operator=(WorkerEventLoop const&) -> WorkerEventLoop& = delete;
    WorkerEventLoop(WorkerEventLoop&&) = delete;
    auto operator=(WorkerEventLoop&&) -> WorkerEventLoop& = delete;

    // Blocks until a shutdown notification is received from main or the
    // IPC channel fails.
    auto run() -> void;

    [[nodiscard]] auto shard_index() const noexcept -> std::uint32_t;

private:
    core::FileDescriptor ipc_fd_;
    core::FileDescriptor ipc_key_fd_;
    core::FileDescriptor db_uri_fd_;
    config::Config config_;
    std::uint32_t threads_{};
    std::uint32_t shard_index_{};
};

} // namespace merovingian::federation_worker
