// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/core/CopyableConditionVariable.hpp"
#include "merovingian/core/CopyableMutex.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <mutex>
#include <thread>
#include <utility>

// Every assertion runs on the test's own thread: Catch2 assertions are not thread-safe. A copy
// or move that shared the source's mutex would deadlock on acquire() and fail as a test timeout.

SCENARIO("A copied or moved CopyableMutex has its own unlocked mutex", "[core][copyable_mutex]")
{
    GIVEN("a mutex that is locked")
    {
        auto source = merovingian::core::CopyableMutex{};
        auto const held = source.acquire();

        WHEN("it is copy-constructed, move-constructed and assigned")
        {
            auto const copy = source;
            auto const moved = merovingian::core::CopyableMutex{std::move(source)};
            auto assigned = merovingian::core::CopyableMutex{};
            assigned = copy;
            assigned = merovingian::core::CopyableMutex{moved};

            THEN("each new object can be locked while the source is held")
            {
                REQUIRE(held.owns_lock());
                REQUIRE(copy.acquire().owns_lock());
                REQUIRE(moved.acquire().owns_lock());
                REQUIRE(assigned.acquire().owns_lock());
            }
        }
    }

    GIVEN("two mutexes, one locked")
    {
        auto target = merovingian::core::CopyableMutex{};
        auto const other = merovingian::core::CopyableMutex{};
        auto const held = target.acquire();

        WHEN("the locked one is assigned from the other")
        {
            target = other;

            THEN("the assignment leaves it locked and the other lockable")
            {
                REQUIRE(held.owns_lock());
                REQUIRE(other.acquire().owns_lock());
            }
        }
    }
}

SCENARIO("CopyableConditionVariable wakes a waiter before its deadline", "[core][copyable_mutex]")
{
    GIVEN("a flag guarded by a mutex and a condition variable")
    {
        auto const mutex = merovingian::core::CopyableMutex{};
        auto const condition = merovingian::core::CopyableConditionVariable{};
        auto ready = false;

        WHEN("another thread sets the flag and notifies")
        {
            auto notifier = std::thread{[&] {
                {
                    auto const lock = mutex.acquire();
                    ready = true;
                }
                condition.notify_all();
            }};
            auto lock = mutex.acquire();
            auto const woke =
                condition.wait_until(lock, std::chrono::steady_clock::now() + std::chrono::seconds{30}, [&] {
                    return ready;
                });
            notifier.join();

            THEN("the wait returns true")
            {
                REQUIRE(woke);
            }
        }

        WHEN("nobody notifies before a short deadline")
        {
            auto lock = mutex.acquire();
            auto const woke =
                condition.wait_until(lock, std::chrono::steady_clock::now() + std::chrono::milliseconds{20}, [&] {
                    return ready;
                });

            THEN("the wait returns false")
            {
                REQUIRE_FALSE(woke);
            }
        }

        WHEN("it is copied and then used while the source's mutex is held")
        {
            auto const copy = condition;
            auto lock = mutex.acquire();
            copy.notify_one();
            auto const woke =
                copy.wait_until(lock, std::chrono::steady_clock::now() + std::chrono::milliseconds{20}, [&] {
                    return ready;
                });

            THEN("the copy is an independent, working condition variable")
            {
                REQUIRE_FALSE(woke);
            }
        }
    }
}
