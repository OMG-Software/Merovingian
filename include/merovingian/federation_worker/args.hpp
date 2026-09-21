// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace merovingian::federation_worker
{

struct ParsedWorkerArgs final
{
    std::optional<std::string> config_path{};
    std::optional<int> ipc_fd{};
    std::optional<int> ipc_key_fd{};
    // ADR-0062 part 2. Present only when main decided the worker needs a
    // separate database connection URI: nullopt is a valid, expected outcome
    // (database.backend=sqlite, or
    // federation.worker.allow_shared_database_credentials=true), not an
    // error — see federation_worker::read_worker_database_uri.
    std::optional<int> db_uri_fd{};
    std::uint32_t shard_index{0U};
    std::optional<std::string> error{};
};

// Parses the merovingian-fed-worker command line.
// Required: --config <path>, --ipc-fd <fd>, and --ipc-key-fd <fd>.
// Optional: --shard <index> (default 0) and --db-uri-fd <fd>.
//
// --ipc-key-fd names the fd the worker reads its IPC auth key from (see
// federation_worker::read_ipc_auth_key) — main writes the key bytes into a
// pipe and passes the read end's fd number here; the worker never opens the
// operator master-key file itself (see ADR-0062). It must be a distinct,
// non-negative, in-range fd number, and — like --ipc-fd — must not name
// stdin/stdout/stderr (0/1/2).
//
// --db-uri-fd is deliberately optional, unlike --ipc-fd/--ipc-key-fd: main
// passes it only when the worker needs a separate, least-privilege database
// connection URI (ADR-0062 part 2); its absence is not itself an error, since
// a SQLite backend or an explicit
// federation.worker.allow_shared_database_credentials=true opt-out are both
// valid reasons for main not to pass one. When present it is validated the
// same way as --ipc-key-fd: non-negative, in-range, not stdin/stdout/stderr,
// and distinct from both --ipc-fd and --ipc-key-fd.
[[nodiscard]] auto parse_worker_args(int argc, char const* const* argv) -> ParsedWorkerArgs;

} // namespace merovingian::federation_worker
