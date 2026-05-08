// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <utility>

namespace merovingian::core {

class FileDescriptor final {
public:
    static constexpr int invalid = -1;

    FileDescriptor() noexcept = default;

    explicit FileDescriptor(int fd) noexcept
        : fd_{fd} {
    }

    FileDescriptor(FileDescriptor const&) = delete;
    auto operator=(FileDescriptor const&) -> FileDescriptor& = delete;

    FileDescriptor(FileDescriptor&& other) noexcept
        : fd_{std::exchange(other.fd_, invalid)} {
    }

    auto operator=(FileDescriptor&& other) noexcept -> FileDescriptor&;

    ~FileDescriptor();

    [[nodiscard]] auto get() const noexcept -> int;
    [[nodiscard]] auto valid() const noexcept -> bool;

    [[nodiscard]] auto release() noexcept -> int;
    auto reset(int fd = invalid) noexcept -> void;

private:
    int fd_{invalid};
};

} // namespace merovingian::core
