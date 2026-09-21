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
    std::uint32_t shard_index{0U};
    std::optional<std::string> error{};
};

// Parses the merovingian-fed-worker command line.
// Required: --config <path>, --ipc-fd <fd>, and --ipc-key-fd <fd>.
// Optional:  --shard <index> (default 0).
//
// --ipc-key-fd names the fd the worker reads its IPC auth key from (see
// federation_worker::read_ipc_auth_key) — main writes the key bytes into a
// pipe and passes the read end's fd number here; the worker never opens the
// operator master-key file itself (see ADR-0062). It must be a distinct,
// non-negative, in-range fd number, and — like --ipc-fd — must not name
// stdin/stdout/stderr (0/1/2).
[[nodiscard]] auto parse_worker_args(int argc, char const* const* argv) -> ParsedWorkerArgs;

} // namespace merovingian::federation_worker
