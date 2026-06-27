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
    WorkerEventLoop(core::FileDescriptor ipc_fd, config::Config config, std::uint32_t threads);
    ~WorkerEventLoop() = default;

    WorkerEventLoop(WorkerEventLoop const&)                    = delete;
    auto operator=(WorkerEventLoop const&) -> WorkerEventLoop& = delete;
    WorkerEventLoop(WorkerEventLoop&&)                         = delete;
    auto operator=(WorkerEventLoop&&) -> WorkerEventLoop&      = delete;

    // Blocks until a shutdown notification is received from main or the
    // IPC channel fails.
    auto run() -> void;

private:
    core::FileDescriptor ipc_fd_;
    config::Config config_;
    std::uint32_t threads_;
};

} // namespace merovingian::federation_worker
