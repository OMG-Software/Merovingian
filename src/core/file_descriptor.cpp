// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/core/file_descriptor.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <climits>
#include <cstdint>
#include <cstdlib>
#include <set>
#include <span>
#include <string>
#include <tuple>
#include <utility>

#include <dirent.h>
#include <fcntl.h>
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

[[nodiscard]] auto FileDescriptor::set_cloexec() noexcept -> bool
{
    if (!valid())
    {
        return false;
    }
    auto const flags = ::fcntl(m_fd, F_GETFD, 0);
    if (flags < 0)
    {
        return false;
    }
    return ::fcntl(m_fd, F_SETFD, flags | FD_CLOEXEC) == 0;
}

namespace
{

    // Fallback when /proc/self/fd and /dev/fd are unavailable. sysconf(_SC_OPEN_MAX)
    // can return a very large value on some kernels (e.g. NetBSD defaults), and a
    // linear fcntl(F_GETFD)/close scan over that whole range can burn several seconds
    // of CPU in a short-lived worker. Cap the scan to the descriptors a worker actually
    // inherits; anything higher is extremely unlikely to hold secrets. Best-effort and
    // noisy on failure: individual errors are ignored.
    auto close_from_max_nfiles(std::set<int> const& keep_open) noexcept -> void
    {
        // On BSDs, F_MAXFD returns the highest currently open fd, so we only need to
        // scan from 0 to that value. This avoids a slow walk over sysconf(_SC_OPEN_MAX)
        // on NetBSD/QEMU where even a 4096-entry scan can consume the worker's CPU budget.
        auto limit = int{0};
#ifdef F_MAXFD
        auto const max_fd = ::fcntl(0, F_MAXFD);
        if (max_fd >= 0)
        {
            limit = max_fd + 1;
        }
        else
#endif
        {
            auto const open_max = ::sysconf(_SC_OPEN_MAX);
            if (open_max <= 0)
            {
                return;
            }
            constexpr auto max_scan = 1024L;
            limit = static_cast<int>(std::min({open_max, static_cast<long>(INT_MAX), max_scan}));
        }

        for (int fd = 0; fd < limit; ++fd)
        {
            if (keep_open.contains(fd))
            {
                continue;
            }
            if (::fcntl(fd, F_GETFD, 0) >= 0)
            {
                std::ignore = ::close(fd);
            }
        }
    }

    // Close every fd returned by a directory walk. `walk_fd` is the DIR* used for
    // readdir and must not be closed by this sweep; it is added to keep_open implicitly.
    auto close_from_directory(int walk_fd, std::set<int> const& keep_open) noexcept -> void
    {
        // On FreeBSD, NetBSD, and OpenBSD /dev/fd contains entries for every
        // possible fd (not only open ones). Iterating fcntl(F_GETFD) on a
        // small, capped range is simpler and race-tolerant on these platforms,
        // so skip the directory walk there.
#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
        std::ignore = ::close(walk_fd);
        close_from_max_nfiles(keep_open);
        return;
#endif

        auto* const dir = ::fdopendir(walk_fd);
        if (dir == nullptr)
        {
            return;
        }
        // Ensure the directory stream is closed on all paths, but not the underlying
        // walk_fd if the caller still owns it. fdopendir took ownership of walk_fd,
        // so closedir will close it; we dup it first so the caller can close it later.
        auto const owned = FileDescriptor{::fcntl(walk_fd, F_DUPFD_CLOEXEC, 0)};
        if (!owned.valid())
        {
            std::ignore = ::closedir(dir);
            return;
        }

        auto keep = keep_open;
        // Do not close the original walk_fd; closedir consumes the fdopendir-owned copy.
        keep.insert(walk_fd);

        while (true)
        {
            errno = 0;
            auto* const entry = ::readdir(dir);
            if (entry == nullptr)
            {
                break;
            }
            if (entry->d_name[0] == '.')
            {
                continue;
            }
            char* end = nullptr;
            auto const fd = static_cast<int>(std::strtol(entry->d_name, &end, 10));
            if (end == entry->d_name || *end != '\0')
            {
                continue;
            }
            if (fd < 0 || keep.contains(fd))
            {
                continue;
            }
            std::ignore = ::close(fd);
        }
        std::ignore = ::closedir(dir);
    }

} // namespace

auto close_all_file_descriptors_except(std::set<int> const& keep_open) noexcept -> void
{
    auto keep = keep_open;
    keep.insert(STDIN_FILENO);
    keep.insert(STDOUT_FILENO);
    keep.insert(STDERR_FILENO);

#if defined(__linux__)
    auto const proc_fd = ::open("/proc/self/fd", O_RDONLY | O_CLOEXEC | O_DIRECTORY);
    if (proc_fd >= 0)
    {
        close_from_directory(proc_fd, keep);
        return;
    }
#elif defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
    auto const dev_fd = ::open("/dev/fd", O_RDONLY | O_CLOEXEC | O_DIRECTORY);
    if (dev_fd >= 0)
    {
        close_from_directory(dev_fd, keep);
        return;
    }
#endif

    close_from_max_nfiles(keep);
}

auto close_all_file_descriptors_except(std::span<int const> keep_open) noexcept -> void
{
    // Do not close the stdio descriptors the worker inherits; callers list the
    // pipe ends that will become stdio after dup2, but add the standard ones
    // explicitly in case a caller forgot.
    auto const is_kept = [keep_open](int fd) noexcept -> bool {
        if (fd == STDIN_FILENO || fd == STDOUT_FILENO || fd == STDERR_FILENO)
        {
            return true;
        }
        for (auto const keep_fd : keep_open)
        {
            if (fd == keep_fd)
            {
                return true;
            }
        }
        return false;
    };

    // On BSDs, F_MAXFD gives the highest currently open descriptor, so we can
    // scan a bounded range. On other platforms, sysconf(_SC_OPEN_MAX) may be
    // huge; cap the scan to the range a short-lived worker actually inherits.
    auto limit = int{0};
#ifdef F_MAXFD
    auto const max_fd = ::fcntl(0, F_MAXFD);
    if (max_fd >= 0)
    {
        limit = max_fd + 1;
    }
    else
#endif
    {
        auto const open_max = ::sysconf(_SC_OPEN_MAX);
        if (open_max <= 0)
        {
            return;
        }
        constexpr auto max_scan = 1024L;
        limit = static_cast<int>(std::min({open_max, static_cast<long>(INT_MAX), max_scan}));
    }

    for (int fd = 0; fd < limit; ++fd)
    {
        if (is_kept(fd))
        {
            continue;
        }
        if (::fcntl(fd, F_GETFD, 0) >= 0)
        {
            std::ignore = ::close(fd);
        }
    }
}

} // namespace merovingian::core
