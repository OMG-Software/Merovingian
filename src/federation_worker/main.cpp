// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/config/config_parser.hpp"
#include "merovingian/core/file_descriptor.hpp"
#include "merovingian/federation_worker/args.hpp"
#include "merovingian/observability/logger.hpp"
#include "worker_event_loop.hpp"

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>

#include <fcntl.h>
#include <unistd.h>

namespace
{

auto read_file(std::string_view path) -> std::optional<std::string>
{
    auto input = std::ifstream{std::string{path}, std::ios::binary};
    if (!input.is_open())
    {
        return std::nullopt;
    }

    // Read in chunks to avoid a GCC -Wnull-dereference false positive that the
    // std::istreambuf_iterator constructor triggers in some libstdc++ builds.
    auto contents = std::string{};
    constexpr auto chunk_size = std::size_t{4096U};
    auto chunk = std::vector<char>(chunk_size);
    while (input.read(chunk.data(), static_cast<std::streamsize>(chunk.size())) || input.gcount() > 0)
    {
        contents.append(chunk.data(), static_cast<std::size_t>(input.gcount()));
    }
    input.close();
    return contents;
}

} // namespace

auto main(int argc, char const* const* argv) -> int
{
    auto const args = merovingian::federation_worker::parse_worker_args(argc, argv);
    if (args.error.has_value())
    {
        std::cerr << "merovingian-fed-worker: " << *args.error << '\n';
        return 1;
    }

    // Validate that the IPC fd is open.
    auto const raw_fd = *args.ipc_fd;
    if (::fcntl(raw_fd, F_GETFD) < 0)
    {
        std::cerr << "merovingian-fed-worker: ipc fd " << raw_fd << " is not open: " << ::strerror(errno) << '\n';
        return 1;
    }

    auto const contents = read_file(*args.config_path);
    if (!contents.has_value())
    {
        std::cerr << "merovingian-fed-worker: cannot open config: " << *args.config_path << '\n';
        return 1;
    }

    auto const parse_result = merovingian::config::parse_key_value_config(*contents);
    if (!parse_result.findings.empty())
    {
        for (auto const& f : parse_result.findings)
        {
            std::cerr << "merovingian-fed-worker: config: " << f.field << ": " << f.message << '\n';
        }
        return 1;
    }

    LOG_INFO("Federation worker starting: shard=" + std::to_string(args.shard_index) + " config=" + *args.config_path +
             " ipc_fd=" + std::to_string(raw_fd));

    auto ipc_fd = merovingian::core::FileDescriptor{raw_fd};
    auto const threads = parse_result.config.federation_worker().threads;

    auto loop = merovingian::federation_worker::WorkerEventLoop{std::move(ipc_fd), parse_result.config, threads,
                                                                args.shard_index};
    loop.run();

    return 0;
}
