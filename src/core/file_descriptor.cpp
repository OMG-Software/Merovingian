// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/core/file_descriptor.hpp"

#include <tuple>
#include <utility>

#include <unistd.h>

namespace merovingian::core
{

FileDescriptor::~FileDescriptor()
{
    reset();
}

auto FileDescriptor::operator=(FileDescriptor&& other) noexcept -> FileDescriptor&
{
    if (this != &other)
    {
        reset();
        m_fd = std::exchange(other.m_fd, invalid);
    }

    return *this;
}

[[nodiscard]] auto FileDescriptor::get() const noexcept -> int
{
    return m_fd;
}

[[nodiscard]] auto FileDescriptor::valid() const noexcept -> bool
{
    return m_fd >= 0;
}

[[nodiscard]] auto FileDescriptor::release() noexcept -> int
{
    return std::exchange(m_fd, invalid);
}

auto FileDescriptor::reset(int fd) noexcept -> void
{
    if (valid())
    {
        std::ignore = ::close(m_fd);
    }

    m_fd = fd;
}

} // namespace merovingian::core
