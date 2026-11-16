// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// ADR-0761: the bounded, expiring record of servers that gave no answer to a remote profile lookup.
// Tags: [homeserver][adr0761].

#include "merovingian/homeserver/RecentlyUnreachableServers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstddef>
#include <string>

using merovingian::homeserver::RecentlyUnreachableServers;

namespace
{

constexpr auto ttl = std::chrono::seconds{60};
auto const start = RecentlyUnreachableServers::Clock::time_point{} + std::chrono::hours{1};

} // namespace

SCENARIO("A server that gave no answer is remembered until its record expires", "[homeserver][adr0761]")
{
    GIVEN("a record with a 60 second lifetime")
    {
        auto servers = RecentlyUnreachableServers{ttl, 8U};

        WHEN("a server is remembered")
        {
            servers.remember("down.example.org", start);

            THEN("it is remembered just before the lifetime ends and not at its end")
            {
                REQUIRE(servers.contains("down.example.org", start));
                REQUIRE(servers.contains("down.example.org", start + ttl - std::chrono::milliseconds{1}));
                REQUIRE_FALSE(servers.contains("down.example.org", start + ttl));
            }

            THEN("another server is not remembered")
            {
                REQUIRE_FALSE(servers.contains("up.example.org", start));
            }
        }

        WHEN("a server is remembered and fails again later")
        {
            servers.remember("down.example.org", start);
            servers.remember("down.example.org", start + std::chrono::seconds{50});

            THEN("the later failure starts its lifetime again, and it is still one entry")
            {
                REQUIRE(servers.contains("down.example.org", start + std::chrono::seconds{100}));
                REQUIRE(servers.size() == 1U);
            }
        }

        WHEN("a remembered server answers and is forgotten")
        {
            servers.remember("down.example.org", start);
            servers.forget("down.example.org");

            THEN("it is no longer remembered")
            {
                REQUIRE_FALSE(servers.contains("down.example.org", start));
                REQUIRE(servers.size() == 0U);
            }
        }
    }
}

SCENARIO("The record of servers that gave no answer never grows past its capacity", "[homeserver][adr0761]")
{
    GIVEN("a record that holds two servers, already full")
    {
        auto servers = RecentlyUnreachableServers{ttl, 2U};
        servers.remember("first.example.org", start);
        servers.remember("second.example.org", start + std::chrono::seconds{10});

        WHEN("a third server fails while both are still live")
        {
            servers.remember("third.example.org", start + std::chrono::seconds{20});

            THEN("the server remembered longest is dropped and the record still holds two")
            {
                auto const now = start + std::chrono::seconds{20};
                REQUIRE(servers.size() == 2U);
                REQUIRE_FALSE(servers.contains("first.example.org", now));
                REQUIRE(servers.contains("second.example.org", now));
                REQUIRE(servers.contains("third.example.org", now));
            }
        }

        WHEN("a third server fails after the first record has expired")
        {
            auto const now = start + ttl + std::chrono::seconds{5};
            servers.remember("third.example.org", now);

            THEN("the expired record makes room and the live one is kept")
            {
                REQUIRE(servers.size() == 2U);
                REQUIRE(servers.contains("second.example.org", now));
                REQUIRE(servers.contains("third.example.org", now));
            }
        }
    }

    GIVEN("a record with no capacity")
    {
        auto servers = RecentlyUnreachableServers{ttl, 0U};

        WHEN("a server fails")
        {
            servers.remember("down.example.org", start);

            THEN("nothing is remembered")
            {
                REQUIRE(servers.size() == 0U);
                REQUIRE_FALSE(servers.contains("down.example.org", start));
            }
        }
    }
}
