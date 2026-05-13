// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/net/shutdown_signal.hpp"

#include <catch2/catch_test_macros.hpp>

#include <poll.h>

SCENARIO("ShutdownSignal is not fired on construction", "[net][shutdown]")
{
    GIVEN("a freshly constructed ShutdownSignal")
    {
        auto signal = merovingian::net::ShutdownSignal{};

        THEN("it is valid, has a readable fd, and is not yet fired")
        {
            REQUIRE(signal.valid());
            REQUIRE(signal.read_fd() >= 0);
            REQUIRE_FALSE(signal.fired());
        }
    }
}

SCENARIO("ShutdownSignal becomes fired and the read fd becomes readable after fire()", "[net][shutdown]")
{
    GIVEN("a ShutdownSignal that has not yet fired")
    {
        auto signal = merovingian::net::ShutdownSignal{};

        WHEN("fire() is invoked")
        {
            signal.fire();

            THEN("fired() returns true and the read fd polls as readable")
            {
                REQUIRE(signal.fired());

                auto poll_entry = pollfd{};
                poll_entry.fd = signal.read_fd();
                poll_entry.events = POLLIN;
                auto const poll_result = ::poll(&poll_entry, 1U, 0);
                REQUIRE(poll_result == 1);
                REQUIRE((poll_entry.revents & POLLIN) != 0);
            }
        }
    }
}

SCENARIO("ShutdownSignal fire() is idempotent", "[net][shutdown]")
{
    GIVEN("a ShutdownSignal that has already fired once")
    {
        auto signal = merovingian::net::ShutdownSignal{};
        signal.fire();
        REQUIRE(signal.fired());

        WHEN("fire() is invoked again")
        {
            signal.fire();

            THEN("the signal remains fired and the fd is still valid")
            {
                REQUIRE(signal.fired());
                REQUIRE(signal.valid());
                REQUIRE(signal.read_fd() >= 0);
            }
        }
    }
}
