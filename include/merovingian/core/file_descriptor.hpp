// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <set>
#include <span>
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
//
// Intended for the brief window between fork() and exec() when sealing a child
// process. Do NOT call this in a long-lived process that keeps using linked
// libraries afterwards: it closes descriptors those libraries cache. In
// particular, on NetBSD libsodium keeps a persistent /dev/urandom descriptor
// (Linux/FreeBSD use the getrandom(2)/arc4random syscalls and hold no fd), so a
// sweep there silently breaks every subsequent libsodium RNG call with
// sodium_misuse() -> abort(). Tests that must exercise the sweep should fork and
// run it in a throwaway child.
auto close_all_file_descriptors_except(std::set<int> const& keep_open) noexcept -> void;

// Allocation-free overload for use after fork() in a multi-threaded process.
// It scans only a bounded range of descriptors using fcntl(F_MAXFD) when
// available, or sysconf(_SC_OPEN_MAX) capped at 1024, so it is safe to call
// between fork() and exec(). It never walks a directory or allocates heap
// memory.
auto close_all_file_descriptors_except(std::span<int const> keep_open) noexcept -> void;

} // namespace merovingian::core
