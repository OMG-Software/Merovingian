// SPDX-License-Identifier: GPL-3.0-or-later

// F-79 (ADR-0409): requests in flight to one push gateway host, and to one resolved address, are
// capped, so many subdomains of one server cannot hold the whole delivery budget between them.

#include "merovingian/push/GatewayInFlightLimiter.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <cstddef>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace
{

using merovingian::push::GatewayInFlightLimiter;

[[nodiscard]] auto keys_of(std::vector<std::string> keys) -> std::vector<std::string>
{
    return keys;
}

} // namespace

SCENARIO("a gateway key refuses a request past its cap and takes it again once one finishes",
         "[push][f79][in-flight-limiter]")
{
    GIVEN("a limiter and a cap of two on one host")
    {
        auto limiter = GatewayInFlightLimiter{};
        auto const host = keys_of({"host:gw.example:443"});
        auto first = limiter.try_acquire(host, 2U);
        auto second = limiter.try_acquire(host, 2U);
        REQUIRE(first.has_value());
        REQUIRE(second.has_value());

        WHEN("a third request asks while the first two are still in flight")
        {
            auto const third = limiter.try_acquire(host, 2U);

            THEN("it is refused and the count is unchanged")
            {
                CHECK_FALSE(third.has_value());
                CHECK(limiter.in_flight("host:gw.example:443") == 2U);
            }
        }

        WHEN("one request finishes and a third asks")
        {
            first.reset();
            auto const third = limiter.try_acquire(host, 2U);

            THEN("it is admitted")
            {
                CHECK(third.has_value());
                CHECK(limiter.in_flight("host:gw.example:443") == 2U);
            }
        }

        WHEN("every request finishes")
        {
            first.reset();
            second.reset();

            THEN("nothing is tracked")
            {
                CHECK(limiter.tracked_keys() == 0U);
            }
        }
    }
}

SCENARIO("a request over the cap on any one of its keys takes none of them", "[push][f79][in-flight-limiter]")
{
    GIVEN("one address already at its cap, and another address free")
    {
        auto limiter = GatewayInFlightLimiter{};
        auto const busy = keys_of({"addr:192.0.2.1"});
        auto held = limiter.try_acquire(busy, 1U);
        REQUIRE(held.has_value());

        WHEN("a request names both addresses")
        {
            auto const both = keys_of({"addr:192.0.2.2", "addr:192.0.2.1"});
            auto const refused = limiter.try_acquire(both, 1U);

            THEN("it is refused and the free address is left untouched")
            {
                CHECK_FALSE(refused.has_value());
                CHECK(limiter.in_flight("addr:192.0.2.2") == 0U);
                CHECK(limiter.in_flight("addr:192.0.2.1") == 1U);
            }
        }
    }
}

SCENARIO("many hosts on one address share that address's cap", "[push][f79][in-flight-limiter]")
{
    GIVEN("three subdomains of one server, resolving to one address, with an address cap of two")
    {
        auto limiter = GatewayInFlightLimiter{};
        auto const address = keys_of({"addr:198.51.100.7"});

        WHEN("each subdomain sends a request")
        {
            auto a = limiter.try_acquire(address, 2U);
            auto b = limiter.try_acquire(address, 2U);
            auto const c = limiter.try_acquire(address, 2U);

            THEN("only two are in flight at that address")
            {
                CHECK(a.has_value());
                CHECK(b.has_value());
                CHECK_FALSE(c.has_value());
            }
        }
    }
}

SCENARIO("a moved slot gives its count back once", "[push][f79][in-flight-limiter]")
{
    GIVEN("a request holding a slot")
    {
        auto limiter = GatewayInFlightLimiter{};
        auto const host = keys_of({"host:gw.example:443"});
        auto slot = limiter.try_acquire(host, 4U);
        REQUIRE(slot.has_value());

        WHEN("the slot is moved and the new owner is destroyed")
        {
            {
                auto moved = std::move(slot);
                CHECK(limiter.in_flight("host:gw.example:443") == 1U);
            }

            THEN("the count is zero, not negative or doubled")
            {
                CHECK(limiter.in_flight("host:gw.example:443") == 0U);
                CHECK(limiter.tracked_keys() == 0U);
            }
        }
    }
}

SCENARIO("concurrent requests never exceed a key's cap", "[push][f79][in-flight-limiter][concurrency]")
{
    GIVEN("eight threads each acquiring and releasing a slot on one key with a cap of three")
    {
        auto limiter = GatewayInFlightLimiter{};
        auto const key = keys_of({"addr:203.0.113.9"});
        auto constexpr cap = std::size_t{3U};
        auto constexpr threads = 8U;
        auto constexpr rounds = 200U;
        auto go = std::atomic<bool>{false};
        auto over_cap = std::atomic<bool>{false};
        auto admitted = std::atomic<unsigned>{0U};

        WHEN("they all start together")
        {
            auto workers = std::vector<std::thread>{};
            workers.reserve(threads);
            for (auto t = 0U; t < threads; ++t)
            {
                workers.emplace_back([&] {
                    while (!go.load())
                    {
                        std::this_thread::yield();
                    }
                    for (auto i = 0U; i < rounds; ++i)
                    {
                        auto slot = limiter.try_acquire(key, cap);
                        if (!slot.has_value())
                        {
                            continue;
                        }
                        admitted.fetch_add(1U);
                        if (limiter.in_flight(key.front()) > cap)
                        {
                            over_cap.store(true);
                        }
                    }
                });
            }
            go.store(true);
            for (auto& worker : workers)
            {
                worker.join();
            }

            THEN("the cap held, some requests were admitted, and nothing is left tracked")
            {
                CHECK_FALSE(over_cap.load());
                CHECK(admitted.load() > 0U);
                CHECK(limiter.tracked_keys() == 0U);
            }
        }
    }
}
