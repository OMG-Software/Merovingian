// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <set>
#include <utility>

namespace merovingian::core
{

class FileDescriptor final
{
public:
    static constexpr int invalid = -1;

    FileDescriptor() noexcept = default;

    explicit FileDescriptor(int fd) noexcept
        : m_fd{fd}
    {
    }

    FileDescriptor(FileDescriptor const&) = delete;
    auto operator=(FileDescriptor const&) -> FileDescriptor& = delete;

    FileDescriptor(FileDescriptor&& other) noexcept
        : m_fd{std::exchange(other.m_fd, invalid)}
    {
    }

    auto operator=(FileDescriptor&& other) noexcept -> FileDescriptor&;

    ~FileDescriptor();

    [[nodiscard]] auto get() const noexcept -> int;
    [[nodiscard]] auto valid() const noexcept -> bool;

    [[nodiscard]] auto release() noexcept -> int;
    auto reset(int fd = invalid) noexcept -> void;

    // Set the FD_CLOEXEC flag on the wrapped descriptor. Returns true on success,
    // false on error or when no descriptor is held.
    [[nodiscard]] auto set_cloexec() noexcept -> bool;

private:
    int m_fd{invalid};
};

// Close every open file descriptor except those listed in `keep_open`.
// Walks /proc/self/fd on Linux, /dev/fd on BSDs, and falls back to iterating
// up to sysconf(_SC_OPEN_MAX) otherwise. Never closes the directory being
// walked. Best-effort: individual close() errors are ignored so the sweep
// completes.
auto close_all_file_descriptors_except(std::set<int> const& keep_open) noexcept -> void;

} // namespace merovingian::core
