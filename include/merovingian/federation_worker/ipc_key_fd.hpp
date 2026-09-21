// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/config/config.hpp"
#include "merovingian/core/file_descriptor.hpp"
#include "merovingian/crypto/ipc_auth_key.hpp"

#include <optional>

namespace merovingian::federation_worker
{

// Reads the IPC auth key that main derived once from the operator master-key
// file and wrote into this inherited pipe fd at spawn time (see
// homeserver::WorkerSupervisor::spawn_and_connect). The worker itself never
// opens the master key file — see ADR-0062, "Federation worker holds no
// secret files; secrets arrive over inherited fds".
//
// Reads exactly crypto::kIpcAuthKeyBytes bytes, then requires the fd to be at
// EOF: a short read (fewer bytes, or main closed its write end early) and a
// long read (more bytes still waiting after the key) are both rejected,
// since either means the two processes disagree about what was sent — never
// silently truncate or take only a prefix. Consumes key_fd and closes it
// before returning, on every path (RAII; also closed explicitly on success so
// the fd is released as soon as the key has been read, not just when the
// caller's core::FileDescriptor eventually goes out of scope).
[[nodiscard]] auto read_ipc_auth_key(core::FileDescriptor key_fd) -> std::optional<crypto::IpcAuthKey>;

// Clears security.secrets.master_key_file on `config` in place. Called by
// WorkerEventLoop::run() right after read_ipc_auth_key succeeds and before
// homeserver::start_runtime() is invoked, so no code path reachable from
// start_runtime() in this worker process can open the operator master-key
// file — see ADR-0062 and docs/threat-model.md, "Worker trust boundary".
// Exposed as its own free function, separate from run()'s other setup, so
// the clearing itself is directly testable without starting a real runtime.
auto clear_master_key_file(config::Config& config) noexcept -> void;

} // namespace merovingian::federation_worker
