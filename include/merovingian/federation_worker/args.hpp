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
    std::uint32_t shard_index{0U};
    std::optional<std::string> error{};
};

// Parses the merovingian-fed-worker command line.
// Required: --config <path> and --ipc-fd <fd>.
// Optional:  --shard <index> (default 0).
[[nodiscard]] auto parse_worker_args(int argc, char const* const* argv) -> ParsedWorkerArgs;

} // namespace merovingian::federation_worker
