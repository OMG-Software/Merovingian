// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// These scenarios validate the TCP-liveness mechanism used by the sync pool's
// zombie-connection reaper: after each poll-interval timeout the sync pool thread
// calls recv(MSG_PEEK | MSG_DONTWAIT) on the raw socket fd to detect whether the
// client has already closed the connection.  When recv returns 0 (EOF) the thread
// exits immediately, freeing itself for the next request instead of waiting for
// a second poll slice.

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cerrno>
#include <sys/socket.h>
#include <unistd.h>

SCENARIO("sync pool liveness check detects a closed peer connection",
         "[sync][pool][liveness]")
{
    GIVEN("a Unix socket pair representing the server fd and the client fd")
    {
        auto fds = std::array<int, 2>{-1, -1};
        REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds.data()) == 0);
        auto const server_fd = fds[0];
        auto const client_fd = fds[1];

        WHEN("the client end is closed (simulating SDK disconnect)")
        {
            ::close(client_fd);

            THEN("MSG_PEEK | MSG_DONTWAIT recv on the server fd returns 0 (EOF)")
            {
                auto buf     = std::array<char, 1>{};
                auto const n = ::recv(server_fd, buf.data(), 1, MSG_PEEK | MSG_DONTWAIT);
                CHECK(n == 0);
                ::close(server_fd);
            }
        }
    }
}

SCENARIO("sync pool liveness check does not falsely report a live connection as closed",
         "[sync][pool][liveness]")
{
    GIVEN("a Unix socket pair with both ends open and no data pending")
    {
        auto fds = std::array<int, 2>{-1, -1};
        REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds.data()) == 0);
        auto const server_fd = fds[0];
        auto const client_fd = fds[1];

        WHEN("MSG_PEEK | MSG_DONTWAIT recv is called with no pending data")
        {
            auto buf         = std::array<char, 1>{};
            auto const n     = ::recv(server_fd, buf.data(), 1, MSG_PEEK | MSG_DONTWAIT);
            auto const saved = errno;

            THEN("recv returns -1 with EAGAIN or EWOULDBLOCK, signalling connection is alive")
            {
                CHECK(n == -1);
                CHECK((saved == EAGAIN || saved == EWOULDBLOCK));
                ::close(server_fd);
                ::close(client_fd);
            }
        }
    }
}

SCENARIO("sync pool liveness check detects connection reset by peer",
         "[sync][pool][liveness]")
{
    GIVEN("a Unix socket pair where the client sends RST (SO_LINGER with l_linger=0)")
    {
        auto fds = std::array<int, 2>{-1, -1};
        REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds.data()) == 0);
        auto const server_fd = fds[0];
        auto const client_fd = fds[1];

        WHEN("the client resets the connection abruptly via SO_LINGER l_linger=0")
        {
            struct ::linger ling = {1, 0};
            ::setsockopt(client_fd, SOL_SOCKET, SO_LINGER, &ling, sizeof(ling));
            ::close(client_fd); // RST sent instead of FIN

            THEN("peek-recv on server fd returns 0 or error — not EAGAIN — indicating peer is gone")
            {
                auto buf     = std::array<char, 1>{};
                auto const n = ::recv(server_fd, buf.data(), 1, MSG_PEEK | MSG_DONTWAIT);
                auto const e = errno;
                // n==0 (FIN) or n<0 with connection error — either signals peer closed
                bool const peer_gone = (n == 0) || (n < 0 && e != EAGAIN && e != EWOULDBLOCK);
                CHECK(peer_gone);
                ::close(server_fd);
            }
        }
    }
}
