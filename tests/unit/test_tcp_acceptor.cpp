// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/net/tcp_acceptor.hpp"

#include <catch2/catch_test_macros.hpp>

SCENARIO("TcpAcceptor binds to an ephemeral loopback port", "[net][acceptor]")
{
    GIVEN("a default-constructed TcpAcceptor")
    {
        auto acceptor = merovingian::net::TcpAcceptor{};

        WHEN("it is bound to 127.0.0.1 on port 0")
        {
            auto const result = acceptor.bind("127.0.0.1", 0U);

            THEN("the bind succeeds and exposes a concrete port")
            {
                REQUIRE(result.ok);
                REQUIRE(result.error.empty());
                REQUIRE(acceptor.valid());
                REQUIRE(acceptor.fd() >= 0);
                REQUIRE(acceptor.bound_port() > 0U);
            }
        }
    }
}

SCENARIO("TcpAcceptor releases the socket on close", "[net][acceptor]")
{
    GIVEN("a bound TcpAcceptor")
    {
        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);

        WHEN("close is invoked")
        {
            acceptor.close();

            THEN("the acceptor reports as invalid and exposes no fd")
            {
                REQUIRE_FALSE(acceptor.valid());
                REQUIRE(acceptor.fd() < 0);
                REQUIRE(acceptor.bound_port() == 0U);
            }
        }
    }
}

SCENARIO("TcpAcceptor fails closed when no local address matches the bind", "[net][acceptor]")
{
    GIVEN("a default-constructed TcpAcceptor")
    {
        auto acceptor = merovingian::net::TcpAcceptor{};

        WHEN("it is bound to an address the local machine cannot own")
        {
            // 240.0.0.1 is reserved IANA space; no host should ever own it.
            auto const result = acceptor.bind("240.0.0.1", 0U);

            THEN("the bind fails closed with a non-empty error and no fd")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE_FALSE(result.error.empty());
                REQUIRE_FALSE(acceptor.valid());
            }
        }
    }
}
