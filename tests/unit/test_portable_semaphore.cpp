// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// Unit tests for core::PortableSemaphore. Worker threads touch only atomics and the semaphore; Catch2
// assertions run on the main thread.

#include "merovingian/core/PortableSemaphore.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <thread>
#include <vector>

SCENARIO("A semaphore with free slots does not block", "[core][semaphore][unit]")
{
    GIVEN("a semaphore with two slots")
    {
        auto semaphore = merovingian::core::PortableSemaphore{2U};

        WHEN("two acquires are made")
        {
            semaphore.acquire();
            semaphore.acquire();

            THEN("both return, and a release makes a slot available again")
            {
                semaphore.release();
                semaphore.acquire();
                SUCCEED("every acquire returned");
            }
        }
    }

    GIVEN("a semaphore with no slots and a release made before anyone waits")
    {
        auto semaphore = merovingian::core::PortableSemaphore{0U};
        semaphore.release();

        WHEN("an acquire is made")
        {
            semaphore.acquire();

            THEN("it returned without waiting")
            {
                SUCCEED("the stored release was used");
            }
        }
    }
}

SCENARIO("A semaphore with no free slot holds a waiter until a release", "[core][semaphore][unit]")
{
    GIVEN("an exhausted semaphore and a thread waiting on it")
    {
        auto semaphore = merovingian::core::PortableSemaphore{1U};
        semaphore.acquire();
        auto passed = std::atomic<bool>{false};
        auto waiter = std::thread{[&semaphore, &passed] {
            semaphore.acquire();
            passed.store(true);
        }};
        std::this_thread::sleep_for(std::chrono::milliseconds{50});
        auto const passed_before_release = passed.load();

        WHEN("a slot is released")
        {
            semaphore.release();
            waiter.join();

            THEN("the waiter had been held, and now has passed")
            {
                REQUIRE_FALSE(passed_before_release);
                REQUIRE(passed.load());
            }
        }
    }

    GIVEN("three waiters on an empty semaphore")
    {
        auto semaphore = merovingian::core::PortableSemaphore{0U};
        auto passed = std::atomic<int>{0};
        auto waiters = std::vector<std::thread>{};
        for (auto i = 0; i < 3; ++i)
        {
            waiters.emplace_back([&semaphore, &passed] {
                semaphore.acquire();
                passed.fetch_add(1);
            });
        }

        WHEN("two slots are released, then the third")
        {
            semaphore.release();
            semaphore.release();
            std::this_thread::sleep_for(std::chrono::milliseconds{100});
            auto const passed_after_two = passed.load();
            semaphore.release();
            for (auto& waiter : waiters)
            {
                waiter.join();
            }

            THEN("one waiter passes per release")
            {
                REQUIRE(passed_after_two == 2);
                REQUIRE(passed.load() == 3);
            }
        }
    }
}
