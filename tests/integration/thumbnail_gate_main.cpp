// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// Test-only exec interposer. Nothing here reads stdin, writes stdout, decodes an
// image or constructs a worker frame. The real worker retains both pipe ends.
#include "merovingian/core/file_descriptor.hpp"

#include <cerrno>
#include <chrono>
#include <filesystem>
#include <tuple>

#include <fcntl.h>
#include <poll.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef MEROVINGIAN_TEST_THUMBNAIL_WORKER
#error "The thumbnail gate requires the actual built thumbnail worker"
#endif

namespace
{
[[nodiscard]] auto is_fifo(merovingian::core::FileDescriptor const& descriptor) noexcept -> bool
{
    struct stat metadata{};
    return descriptor.valid() && ::fstat(descriptor.get(), &metadata) == 0 && S_ISFIFO(metadata.st_mode);
}

[[nodiscard]] auto run_gate(std::filesystem::path const& executable) -> int
{
    if (!executable.is_absolute())
    {
        return 120;
    }
    auto const directory = executable.parent_path();
    // Open the release reader BEFORE acknowledging entry. The parent owns
    // O_RDWR keepalives, so neither open waits for its counterpart.
    auto release = merovingian::core::FileDescriptor{
        ::open((directory / "thumbnail-gate.release").c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC)};
    auto ack = merovingian::core::FileDescriptor{
        ::open((directory / "thumbnail-gate.ack").c_str(), O_WRONLY | O_NONBLOCK | O_CLOEXEC)};
    if (!is_fifo(release) || !is_fifo(ack))
    {
        return 121;
    }
    auto const entered = 'A';
    auto acknowledged = ssize_t{-1};
    do
    {
        acknowledged = ::write(ack.get(), &entered, 1U);
    } while (acknowledged < 0 && errno == EINTR);
    if (acknowledged != 1)
    {
        return 122;
    }
    ack.reset();

    auto const deadline = std::chrono::steady_clock::now() + std::chrono::seconds{60};
    while (true)
    {
        auto const remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
        if (remaining.count() <= 0)
        {
            return 123;
        }
        auto entry = ::pollfd{release.get(), POLLIN, 0};
        auto const ready = ::poll(&entry, 1U, static_cast<int>(remaining.count()));
        if (ready < 0 && errno == EINTR)
        {
            continue;
        }
        if (ready <= 0 || (entry.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0)
        {
            return 124;
        }
        auto command = char{};
        auto const received = ::read(release.get(), &command, 1U);
        if (received < 0 && (errno == EINTR || errno == EAGAIN))
        {
            continue;
        }
        if (received != 1 || command != 'R')
        {
            return 125;
        }
        break;
    }
    release.reset();
    // The parent supplies only argv[0] and a minimal PATH environment. Locate
    // controls from that copied executable, not environment or inherited fds.
    // All controls are closed before exec; stdin/stdout are never touched.
    std::ignore =
        ::execl(MEROVINGIAN_TEST_THUMBNAIL_WORKER, MEROVINGIAN_TEST_THUMBNAIL_WORKER, static_cast<char*>(nullptr));
    return 126;
}
} // namespace

// argv is the non-owning process ABI, not owned storage.
auto main(int argc, char** argv) -> int
{
    try
    {
        if (argc != 1 || argv == nullptr || argv[0] == nullptr)
        {
            return 119;
        }
        return run_gate(std::filesystem::path{argv[0]});
    }
    catch (...)
    {
        return 127;
    }
}
