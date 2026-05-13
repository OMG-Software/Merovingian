// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/core/file_descriptor.hpp"

namespace merovingian::core
{

class SocketHandle final
{
public:
    SocketHandle() noexcept = default;

    explicit SocketHandle(int fd) noexcept
        : m_fd{fd}
    {
    }

    SocketHandle(SocketHandle const&) = delete;
    auto operator=(SocketHandle const&) -> SocketHandle& = delete;

    SocketHandle(SocketHandle&&) noexcept = default;
    auto operator=(SocketHandle&&) noexcept -> SocketHandle& = default;

    ~SocketHandle() = default;

    [[nodiscard]] auto native_handle() const noexcept -> int
    {
        return m_fd.get();
    }

    [[nodiscard]] auto valid() const noexcept -> bool
    {
        return m_fd.valid();
    }

private:
    FileDescriptor m_fd{};
};

} // namespace merovingian::core
