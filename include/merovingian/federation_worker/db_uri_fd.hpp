// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/config/config.hpp"
#include "merovingian/core/file_descriptor.hpp"
#include "merovingian/core/secret_buffer.hpp"

#include <cstddef>
#include <optional>
#include <string_view>

namespace merovingian::federation_worker
{

// Bound on the accepted database connection URI, in bytes. A real PostgreSQL
// libpq connection string is far smaller than this; the cap exists only so a
// misbehaving or compromised main process cannot make the worker allocate an
// unbounded buffer over this pipe. See read_worker_database_uri.
inline constexpr std::size_t kMaxWorkerDatabaseUriBytes{4096U};

// Reads the database connection URI main derived for this worker's separate,
// least-privilege PostgreSQL login (ADR-0062 part 2) and wrote into this
// inherited pipe fd at spawn time — see
// homeserver::WorkerSupervisor::spawn_and_connect and
// homeserver::WorkerPool::WorkerPool. The worker itself never opens
// federation.worker.database_uri_file.
//
// Unlike read_ipc_auth_key, the URI has no fixed length, so this reads until
// EOF instead of a fixed byte count, rejecting anything larger than
// kMaxWorkerDatabaseUriBytes (fail closed rather than silently truncating)
// and rejecting an empty result. Consumes uri_fd and closes it before
// returning, on every path (RAII; also closed explicitly on success so the
// fd is released as soon as the URI has been read).
[[nodiscard]] auto read_worker_database_uri(core::FileDescriptor uri_fd) -> std::optional<core::SecretBuffer>;

// Applies a fd-delivered database URI onto the worker's own in-memory Config
// copy: `config.database().worker_conninfo_override` is set to `uri`, and
// `uri_file`, `runtime_role`, and `migration_role` are all cleared. The
// separate least-privilege role connects directly with its own grants, so no
// SET ROLE dance is attempted against a role that role was never granted
// membership of; clearing uri_file means no later code path in this process
// has a path string to pass to database::open_postgresql_persistent_store's
// file-reading caller even if it tried. Called by WorkerEventLoop::run()
// right after read_worker_database_uri succeeds and before
// homeserver::start_runtime() is invoked. See ADR-0062 part 2 and
// docs/threat-model.md, "Worker trust boundary".
auto apply_worker_database_uri(config::Config& config, std::string_view uri) -> void;

} // namespace merovingian::federation_worker
