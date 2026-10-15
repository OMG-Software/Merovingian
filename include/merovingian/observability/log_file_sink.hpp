// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cerrno>
#include <cstddef>
#include <string>
#include <string_view>
#include <utility>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace merovingian::observability
{

// The operator's `--log-file` (ISO-6, ADR-0146). The path is opened without
// following a symbolic link in its final component, close-on-exec, and only
// when it names a regular file this process owns; the file is then made 0600
// whatever the umask, and truncated, as the stream it replaces did. Anything
// else (a symlink, FIFO, device or another user's file) is refused and the
// sink stays closed, so the logger simply has no file output.
//
// Writes are buffered up to `buffer_limit` bytes and written with write(2) on
// flush(), on overflow and on close. A failed write drops the pending bytes:
// logging must never stop the server. Not thread-safe; SingleLog serialises
// every call under its file lock.
//
// Header-only, like logger.hpp, so that every executable using the logger
// gets it without linking the observability library.
class LogFileSink final
{
public:
    static constexpr std::size_t buffer_limit = 10240U;

    LogFileSink() noexcept = default;

    ~LogFileSink()
    {
        close();
    }

    LogFileSink(LogFileSink const&) = delete;
    auto operator=(LogFileSink const&) -> LogFileSink& = delete;
    LogFileSink(LogFileSink&&) = delete;
    auto operator=(LogFileSink&&) -> LogFileSink& = delete;

    // Closes any open file first. Returns whether the new path was opened.
    [[nodiscard]] auto open(std::string const& path) -> bool
    {
        close();
        if (path.empty() || path.find('\0') != std::string::npos)
        {
            return false;
        }
        // O_NONBLOCK so a FIFO with no reader is refused below rather than
        // blocking start-up inside open(); it is cleared for the regular file.
        // No O_TRUNC: nothing is truncated until the file is known to be ours.
        auto fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_NOFOLLOW | O_CLOEXEC | O_NOCTTY | O_NONBLOCK, 0600);
        if (fd < 0)
        {
            return false;
        }
        struct stat metadata{};
        auto const flags = ::fcntl(fd, F_GETFL);
        auto const owned_regular_file = flags >= 0 && ::fstat(fd, &metadata) == 0 && S_ISREG(metadata.st_mode) &&
                                        metadata.st_uid == ::geteuid();
        if (!owned_regular_file || ::fchmod(fd, 0600) != 0 || ::fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) != 0 ||
            ::ftruncate(fd, 0) != 0)
        {
            ::close(fd);
            return false;
        }
        m_fd = fd;
        return true;
    }

    [[nodiscard]] auto is_open() const noexcept -> bool
    {
        return m_fd >= 0;
    }

    auto write(std::string_view text) -> void
    {
        if (m_fd < 0)
        {
            return;
        }
        m_pending.append(text);
        if (m_pending.size() >= buffer_limit)
        {
            flush();
        }
    }

    auto flush() noexcept -> void
    {
        auto offset = std::size_t{0};
        while (m_fd >= 0 && offset < m_pending.size())
        {
            auto const written = ::write(m_fd, m_pending.data() + offset, m_pending.size() - offset);
            if (written < 0 && errno == EINTR)
            {
                continue;
            }
            if (written <= 0)
            {
                break;
            }
            offset += static_cast<std::size_t>(written);
        }
        m_pending.clear();
    }

    // Flushes, then closes. Safe to call when nothing is open.
    auto close() noexcept -> void
    {
        flush();
        if (auto const fd = std::exchange(m_fd, -1); fd >= 0)
        {
            ::close(fd);
        }
    }

private:
    int m_fd{-1};
    std::string m_pending{};
};

} // namespace merovingian::observability
