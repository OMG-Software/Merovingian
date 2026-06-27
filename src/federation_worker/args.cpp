// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation_worker/args.hpp"

#include <cstdint>
#include <string>
#include <string_view>

namespace merovingian::federation_worker
{

auto parse_worker_args(int argc, char const* const* argv) -> ParsedWorkerArgs
{
    auto parsed = ParsedWorkerArgs{};
    for (auto i = 1; i < argc; ++i)
    {
        auto const arg = std::string_view{argv[i]};
        if (arg == "--config" && i + 1 < argc)
        {
            parsed.config_path = argv[++i];
        }
        else if (arg == "--ipc-fd" && i + 1 < argc)
        {
            auto const val = std::string_view{argv[++i]};
            auto fd = 0;
            auto overflow = false;
            for (auto const ch : val)
            {
                if (ch < '0' || ch > '9')
                {
                    parsed.error = "--ipc-fd requires a non-negative integer";
                    return parsed;
                }
                fd = fd * 10 + (ch - '0');
                if (fd > 65535)
                {
                    overflow = true;
                }
            }
            if (overflow)
            {
                parsed.error = "--ipc-fd value out of range";
                return parsed;
            }
            parsed.ipc_fd = fd;
        }
        else if (arg == "--shard" && i + 1 < argc)
        {
            auto const val = std::string_view{argv[++i]};
            auto parsed_index = std::uint32_t{0U};
            auto ok = true;
            for (auto const ch : val)
            {
                if (ch < '0' || ch > '9')
                {
                    ok = false;
                    break;
                }
                parsed_index = (parsed_index * 10U) + static_cast<std::uint32_t>(ch - '0');
            }
            if (!ok)
            {
                parsed.error = "--shard requires a non-negative integer";
                return parsed;
            }
            parsed.shard_index = parsed_index;
        }
        else
        {
            parsed.error = "unknown argument: " + std::string{arg};
            return parsed;
        }
    }
    if (!parsed.config_path.has_value())
    {
        parsed.error = "--config is required";
    }
    else if (!parsed.ipc_fd.has_value())
    {
        parsed.error = "--ipc-fd is required";
    }
    return parsed;
}

} // namespace merovingian::federation_worker
