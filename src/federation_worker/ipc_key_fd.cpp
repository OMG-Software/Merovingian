// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation_worker/ipc_key_fd.hpp"

#include "merovingian/core/secret_buffer.hpp"

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <span>

#include <unistd.h>

namespace merovingian::federation_worker
{

namespace
{

    // Reads exactly buffer.size() bytes from fd, retrying on EINTR and on a
    // partial read. Returns false on any error or on a short read (fd closed
    // before the full buffer was filled).
    [[nodiscard]] auto read_exact(int fd, std::span<std::uint8_t> buffer) noexcept -> bool
    {
        auto total_read = std::size_t{0U};
        while (total_read < buffer.size())
        {
            auto const rc = ::read(fd, buffer.data() + total_read, buffer.size() - total_read);
            if (rc < 0)
            {
                if (errno == EINTR)
                {
                    continue;
                }
                return false;
            }
            if (rc == 0)
            {
                // Peer closed before sending the full buffer: a short read.
                return false;
            }
            total_read += static_cast<std::size_t>(rc);
        }
        return true;
    }

    // True only if a subsequent read on fd returns exactly 0 (EOF). A read
    // error is treated as "EOF not confirmed" so the caller fails closed
    // rather than accepting a key it cannot actually prove was the only
    // thing written to the pipe.
    [[nodiscard]] auto fd_is_at_eof(int fd) noexcept -> bool
    {
        auto probe = std::array<std::uint8_t, 1U>{};
        for (;;)
        {
            auto const rc = ::read(fd, probe.data(), probe.size());
            if (rc < 0)
            {
                if (errno == EINTR)
                {
                    continue;
                }
                return false;
            }
            return rc == 0;
        }
    }

} // namespace

auto read_ipc_auth_key(core::FileDescriptor key_fd) -> std::optional<crypto::IpcAuthKey>
{
    auto key_material = core::SecretBuffer{crypto::kIpcAuthKeyBytes};
    if (!read_exact(key_fd.get(), key_material.bytes()))
    {
        return std::nullopt;
    }
    if (!fd_is_at_eof(key_fd.get()))
    {
        return std::nullopt;
    }
    // Explicit close on the success path: release the fd as soon as the key
    // has been fully consumed rather than waiting for key_fd's own
    // destructor. key_fd is also RAII (core::FileDescriptor), so every other
    // return path above still closes it.
    key_fd.reset();

    return crypto::ipc_auth_key_from_bytes(key_material.bytes());
}

auto clear_master_key_file(config::Config& config) noexcept -> void
{
    config.security().secrets.master_key_file.clear();
}

} // namespace merovingian::federation_worker
