// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/core/file_descriptor.hpp>

#include <unistd.h>

#include <utility>

namespace merovingian::core {

FileDescriptor::~FileDescriptor() {
    reset();
}

auto FileDescriptor::operator=(FileDescriptor&& other) noexcept -> FileDescriptor& {
    if (this != &other) {
        reset();
        fd_ = std::exchange(other.fd_, invalid);
    }

    return *this;
}

[[nodiscard]] auto FileDescriptor::get() const noexcept -> int {
    return fd_;
}

[[nodiscard]] auto FileDescriptor::valid() const noexcept -> bool {
    return fd_ >= 0;
}

[[nodiscard]] auto FileDescriptor::release() noexcept -> int {
    return std::exchange(fd_, invalid);
}

auto FileDescriptor::reset(int fd) noexcept -> void {
    if (valid()) {
        static_cast<void>(::close(fd_));
    }

    fd_ = fd;
}

} // namespace merovingian::core
