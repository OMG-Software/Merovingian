// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation_worker/db_uri_fd.hpp"

#include "merovingian/core/secret_buffer.hpp"

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include <unistd.h>

namespace merovingian::federation_worker
{

namespace
{

    constexpr auto kReadChunkBytes = std::size_t{256U};

} // namespace

auto read_worker_database_uri(core::FileDescriptor uri_fd) -> std::optional<core::SecretBuffer>
{
    auto buffer = std::vector<std::uint8_t>{};
    buffer.reserve(kMaxWorkerDatabaseUriBytes);
    auto chunk = std::array<std::uint8_t, kReadChunkBytes>{};

    for (;;)
    {
        auto const rc = ::read(uri_fd.get(), chunk.data(), chunk.size());
        if (rc < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            core::secure_zero(std::as_writable_bytes(std::span{buffer}));
            return std::nullopt;
        }
        if (rc == 0)
        {
            // EOF: the URI is exactly what has been accumulated so far.
            break;
        }
        auto const received = static_cast<std::size_t>(rc);
        if (buffer.size() + received > kMaxWorkerDatabaseUriBytes)
        {
            // Fail closed rather than silently accepting a prefix of
            // whatever main sent — a truncated connection string could
            // still parse and quietly connect to the wrong database.
            core::secure_zero(std::as_writable_bytes(std::span{buffer}));
            return std::nullopt;
        }
        buffer.insert(buffer.end(), chunk.begin(), chunk.begin() + static_cast<std::ptrdiff_t>(received));
    }

    if (buffer.empty())
    {
        return std::nullopt;
    }

    // Explicit close on the success path: release the fd as soon as the URI
    // has been fully consumed rather than waiting for uri_fd's own
    // destructor. uri_fd is also RAII (core::FileDescriptor), so every other
    // return path above still closes it.
    uri_fd.reset();

    auto secret = core::SecretBuffer{
        std::span<std::uint8_t const>{buffer.data(), buffer.size()}
    };
    core::secure_zero(std::as_writable_bytes(std::span{buffer}));
    return secret;
}

auto apply_worker_database_uri(config::Config& config, std::string_view uri) -> void
{
    config.database().worker_conninfo_override = std::string{uri};
    config.database().uri_file.clear();
    config.database().runtime_role.clear();
    config.database().migration_role.clear();
}

} // namespace merovingian::federation_worker
