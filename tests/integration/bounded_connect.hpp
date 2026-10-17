// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

// A loopback connect for integration tests that cannot hang the test binary.
//
// A blocking connect() sleeps in the kernel with no deadline until the socket
// leaves the connecting state; TCP's connection-establishment timer only ends
// a connection that never establishes. On OpenBSD 7.9 CI a blocking connect()
// to the test's own in-process listener never returned, so meson killed the
// whole integration binary after 1800 s. Here the connect is non-blocking and
// completion is polled in short slices against a deadline, so a missed wakeup
// costs one slice, and a connect that cannot complete fails the scenario.

#include <cerrno>
#include <chrono>

#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>

namespace merovingian::tests
{

// Connects `fd` to `address` within `budget`. The descriptor keeps its own
// blocking mode afterwards, so callers that rely on blocking I/O with
// SO_RCVTIMEO/SO_SNDTIMEO behave as before. Returns whether it connected.
[[nodiscard]] inline auto connect_within(int fd, sockaddr const& address, socklen_t length,
                                         std::chrono::milliseconds budget = std::chrono::seconds{5}) -> bool
{
    auto const flags = ::fcntl(fd, F_GETFL);
    if (flags < 0 || ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0)
    {
        return false;
    }
    auto connected = ::connect(fd, &address, length) == 0;
    // A non-blocking connect interrupted by a signal still completes on its own.
    if (!connected && (errno == EINPROGRESS || errno == EINTR))
    {
        auto const deadline = std::chrono::steady_clock::now() + budget;
        while (std::chrono::steady_clock::now() < deadline)
        {
            auto entry = pollfd{fd, POLLOUT, 0};
            auto const ready = ::poll(&entry, 1U, 100);
            if (ready < 0 && errno != EINTR)
            {
                break;
            }
            if (ready > 0)
            {
                auto error = 0;
                auto size = socklen_t{sizeof(error)};
                connected = ::getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size) == 0 && error == 0;
                break;
            }
        }
    }
    auto const restored = ::fcntl(fd, F_SETFL, flags) == 0;
    return connected && restored;
}

} // namespace merovingian::tests
