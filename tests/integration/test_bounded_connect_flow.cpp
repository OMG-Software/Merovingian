// SPDX-License-Identifier: GPL-3.0-or-later

// The integration suite's loopback connect must end, connected or not, within
// its budget: a blocking connect() that never returned on OpenBSD 7.9 CI held
// the whole integration binary until meson killed it.

#include "bounded_connect.hpp"
#include "merovingian/core/file_descriptor.hpp"
#include "merovingian/net/tcp_acceptor.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstdint>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace
{
[[nodiscard]] auto loopback(std::uint16_t port) -> sockaddr_in
{
    auto address = sockaddr_in{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(port);
    return address;
}

[[nodiscard]] auto as_sockaddr(sockaddr_in const& address) -> sockaddr const&
{
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return *reinterpret_cast<sockaddr const*>(&address);
}
} // namespace

SCENARIO("A bounded loopback connect ends within its budget and keeps the descriptor's blocking mode",
         "[integration][test-support][bounded-connect]")
{
    using namespace std::chrono_literals;
    GIVEN("a blocking client socket")
    {
        auto client = merovingian::core::FileDescriptor{::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0)};
        REQUIRE(client.valid());
        auto const flags_before = ::fcntl(client.get(), F_GETFL);
        REQUIRE(flags_before >= 0);
        REQUIRE((flags_before & O_NONBLOCK) == 0);

        WHEN("it connects to a loopback listener")
        {
            auto acceptor = merovingian::net::TcpAcceptor{};
            REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
            auto const address = loopback(acceptor.bound_port());
            auto const connected =
                merovingian::tests::connect_within(client.get(), as_sockaddr(address), sizeof(address));

            THEN("it is connected, still blocking, and can carry bytes to the listener")
            {
                REQUIRE(connected);
                CHECK(::fcntl(client.get(), F_GETFL) == flags_before);
                auto const accepted = merovingian::core::FileDescriptor{::accept(acceptor.fd(), nullptr, nullptr)};
                REQUIRE(accepted.valid());
                auto const byte = char{'x'};
                REQUIRE(::send(client.get(), &byte, 1U, MSG_NOSIGNAL) == 1);
                auto received = char{};
                CHECK(::recv(accepted.get(), &received, 1U, 0) == 1);
                CHECK(received == 'x');
            }
        }

        WHEN("it connects to a loopback port nothing listens on")
        {
            // Bound but never listening: the port is reserved and refuses SYNs.
            auto reserved = merovingian::core::FileDescriptor{::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0)};
            REQUIRE(reserved.valid());
            auto any = loopback(0U);
            REQUIRE(::bind(reserved.get(), &as_sockaddr(any), sizeof(any)) == 0);
            auto bound = sockaddr_in{};
            auto bound_length = socklen_t{sizeof(bound)};
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
            REQUIRE(::getsockname(reserved.get(), reinterpret_cast<sockaddr*>(&bound), &bound_length) == 0);
            auto const started = std::chrono::steady_clock::now();
            auto const connected =
                merovingian::tests::connect_within(client.get(), as_sockaddr(bound), sizeof(bound), 2s);
            auto const elapsed = std::chrono::steady_clock::now() - started;

            THEN("it reports failure within the budget and leaves the descriptor blocking")
            {
                CHECK_FALSE(connected);
                CHECK(elapsed < 3s);
                CHECK(::fcntl(client.get(), F_GETFL) == flags_before);
            }
        }
    }
}
