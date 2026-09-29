// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// 0.12.13 audit item 1: a per-IP cap on open connections, decided at accept
// time, with IPv6 clients grouped by prefix. Tags: [http][connection_limit].

#include "../support/joining_threads.hpp"
#include "merovingian/http/client_address.hpp"
#include "merovingian/http/connection_limiter.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <latch>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using merovingian::http::client_address_key;
using merovingian::http::ConnectionLimiter;

SCENARIO("Client addresses are keyed for per-client limits", "[http][connection_limit]")
{
    GIVEN("the default IPv6 prefix of /64")
    {
        auto const prefix = merovingian::http::default_ipv6_client_prefix_length;

        THEN("an IPv4 address is its own key")
        {
            REQUIRE(client_address_key("203.0.113.7", prefix) == "203.0.113.7");
            REQUIRE(client_address_key("203.0.113.7", prefix) != client_address_key("203.0.113.8", prefix));
        }

        THEN("two IPv6 addresses in one /64 share a key")
        {
            REQUIRE(client_address_key("2001:db8:1:2:aaaa::1", prefix) ==
                    client_address_key("2001:db8:1:2:bbbb:cccc:dddd:eeee", prefix));
            REQUIRE(client_address_key("2001:db8:1:2::1", prefix) == "2001:db8:1:2::/64");
        }

        THEN("IPv6 addresses in different /64s do not share a key")
        {
            REQUIRE(client_address_key("2001:db8:1:2::1", prefix) != client_address_key("2001:db8:1:3::1", prefix));
        }

        THEN("an IPv4-mapped IPv6 address is keyed as the IPv4 address it carries")
        {
            REQUIRE(client_address_key("::ffff:203.0.113.7", prefix) == "203.0.113.7");
        }

        THEN("a value that is not an IP literal is keyed unchanged")
        {
            REQUIRE(client_address_key("unknown", prefix) == "unknown");
            REQUIRE(client_address_key("", prefix).empty());
        }
    }

    GIVEN("other configured IPv6 prefixes")
    {
        THEN("/128 keys every IPv6 address separately")
        {
            REQUIRE(client_address_key("2001:db8::1", 128U) != client_address_key("2001:db8::2", 128U));
            REQUIRE(client_address_key("2001:db8::1", 128U) == "2001:db8::1/128");
        }

        THEN("/48 groups addresses from different /64s of one /48")
        {
            REQUIRE(client_address_key("2001:db8:1:2::1", 48U) == client_address_key("2001:db8:1:ffff::1", 48U));
            REQUIRE(client_address_key("2001:db8:1:2::1", 48U) == "2001:db8:1::/48");
        }

        THEN("out-of-range prefixes are clamped to 1..128")
        {
            REQUIRE(client_address_key("2001:db8::1", 0U) == client_address_key("2001:db8::1", 1U));
            REQUIRE(client_address_key("2001:db8::1", 200U) == client_address_key("2001:db8::1", 128U));
        }
    }
}

SCENARIO("The connection limiter caps open connections per key", "[http][connection_limit]")
{
    GIVEN("a limiter and a cap of two")
    {
        auto limiter = ConnectionLimiter{};
        constexpr auto cap = std::uint32_t{2U};

        WHEN("one address opens three connections while another opens one")
        {
            auto first = limiter.try_acquire("198.51.100.1", cap);
            auto second = limiter.try_acquire("198.51.100.1", cap);
            auto third = limiter.try_acquire("198.51.100.1", cap);
            auto other = limiter.try_acquire("198.51.100.2", cap);

            THEN("the third from the first address is refused and the other address is admitted")
            {
                REQUIRE(first.has_value());
                REQUIRE(second.has_value());
                REQUIRE_FALSE(third.has_value());
                REQUIRE(other.has_value());
                REQUIRE(limiter.active("198.51.100.1") == 2U);
                REQUIRE(limiter.active("198.51.100.2") == 1U);
            }
        }

        WHEN("a connection at the cap is closed")
        {
            auto first = limiter.try_acquire("198.51.100.1", cap);
            auto second = limiter.try_acquire("198.51.100.1", cap);
            REQUIRE(first.has_value());
            REQUIRE(second.has_value());
            second.reset();

            THEN("its slot is free for a new connection")
            {
                REQUIRE(limiter.active("198.51.100.1") == 1U);
                REQUIRE(limiter.try_acquire("198.51.100.1", cap).has_value());
            }
        }

        WHEN("every connection of a key is closed")
        {
            {
                auto first = limiter.try_acquire("198.51.100.1", cap);
                auto second = limiter.try_acquire("198.51.100.1", cap);
                REQUIRE(limiter.tracked_keys() == 1U);
            }

            THEN("the key is no longer tracked")
            {
                REQUIRE(limiter.active("198.51.100.1") == 0U);
                REQUIRE(limiter.tracked_keys() == 0U);
            }
        }

        WHEN("a slot is moved to a new owner and both are destroyed")
        {
            {
                auto acquired = limiter.try_acquire("198.51.100.1", cap);
                REQUIRE(acquired.has_value());
                auto moved = std::move(*acquired);
                acquired.reset();
                REQUIRE(limiter.active("198.51.100.1") == 1U);
            }

            THEN("the count is released exactly once")
            {
                REQUIRE(limiter.active("198.51.100.1") == 0U);
            }
        }

        WHEN("the cap is zero")
        {
            auto refused = limiter.try_acquire("198.51.100.1", 0U);

            THEN("nothing is admitted")
            {
                REQUIRE_FALSE(refused.has_value());
                REQUIRE(limiter.active("198.51.100.1") == 0U);
            }
        }
    }
}

SCENARIO("The connection limiter never admits more than the cap under concurrent use",
         "[http][connection_limit][concurrency]")
{
    GIVEN("a cap of eight and thirty-two threads contending for one key")
    {
        auto limiter = ConnectionLimiter{};
        constexpr auto cap = std::uint32_t{8U};
        constexpr auto thread_count = std::size_t{32U};
        constexpr auto rounds = std::size_t{200U};

        WHEN("every thread repeatedly acquires, checks and releases a slot")
        {
            auto start = std::latch{static_cast<std::ptrdiff_t>(thread_count)};
            auto over_cap = std::vector<std::size_t>(thread_count, 0U);
            auto admitted = std::vector<std::size_t>(thread_count, 0U);
            {
                auto threads = merovingian::tests::JoiningThreads{};
                for (auto index = std::size_t{0U}; index < thread_count; ++index)
                {
                    threads.emplace_back([&, index]() {
                        start.arrive_and_wait();
                        for (auto round = std::size_t{0U}; round < rounds; ++round)
                        {
                            auto const slot = limiter.try_acquire("192.0.2.1", cap);
                            if (slot.has_value())
                            {
                                ++admitted[index];
                                if (limiter.active("192.0.2.1") > cap)
                                {
                                    ++over_cap[index];
                                }
                            }
                        }
                    });
                }
            }

            THEN("the count never exceeded the cap, some were admitted, and all slots were returned")
            {
                auto total_admitted = std::size_t{0U};
                for (auto index = std::size_t{0U}; index < thread_count; ++index)
                {
                    REQUIRE(over_cap[index] == 0U);
                    total_admitted += admitted[index];
                }
                REQUIRE(total_admitted > 0U);
                REQUIRE(limiter.active("192.0.2.1") == 0U);
                REQUIRE(limiter.tracked_keys() == 0U);
            }
        }
    }
}
