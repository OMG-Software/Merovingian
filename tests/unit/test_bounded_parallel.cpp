// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/core/bounded_parallel.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <stdexcept>
#include <thread>
#include <vector>

namespace
{

// Catch2 assertions are not thread-safe: tasks only record into atomics, and
// every assertion runs on the test's own thread after run_bounded_parallel returns.
struct Concurrency final
{
    std::atomic<int> active{0};
    std::atomic<int> peak{0};

    auto enter() -> void
    {
        auto const now = active.fetch_add(1) + 1;
        auto seen = peak.load();
        while (now > seen && !peak.compare_exchange_weak(seen, now))
        {
        }
    }

    auto leave() -> void
    {
        active.fetch_sub(1);
    }
};

} // namespace

SCENARIO("Bounded parallel runs every task once with no more than the given number at a time",
         "[core][bounded_parallel]")
{
    GIVEN("eight tasks and a parallelism of three")
    {
        auto constexpr task_count = std::size_t{8U};
        auto runs = std::vector<std::atomic<int>>(task_count);
        auto concurrency = Concurrency{};

        WHEN("they are run")
        {
            merovingian::core::run_bounded_parallel(task_count, 3U, [&](std::size_t const index) {
                concurrency.enter();
                std::this_thread::sleep_for(std::chrono::milliseconds{20});
                runs[index].fetch_add(1);
                concurrency.leave();
            });

            THEN("each task ran exactly once and at most three ran at the same time")
            {
                REQUIRE(std::ranges::all_of(runs, [](std::atomic<int> const& count) {
                    return count.load() == 1;
                }));
                REQUIRE(concurrency.peak.load() <= 3);
                REQUIRE(concurrency.active.load() == 0);
            }
        }
    }

    GIVEN("no tasks")
    {
        auto calls = std::atomic<int>{0};

        WHEN("they are run")
        {
            merovingian::core::run_bounded_parallel(0U, 4U, [&](std::size_t) {
                calls.fetch_add(1);
            });

            THEN("nothing runs")
            {
                REQUIRE(calls.load() == 0);
            }
        }
    }

    GIVEN("three tasks and a parallelism of zero")
    {
        auto calls = std::atomic<int>{0};

        WHEN("they are run")
        {
            merovingian::core::run_bounded_parallel(3U, 0U, [&](std::size_t) {
                calls.fetch_add(1);
            });

            THEN("every task still runs, one at a time")
            {
                REQUIRE(calls.load() == 3);
            }
        }
    }
}

SCENARIO("A task that throws gives its slot back", "[core][bounded_parallel]")
{
    GIVEN("six tasks that all throw and a parallelism of two")
    {
        auto started = std::atomic<int>{0};
        auto const throwing = [&](std::size_t) {
            started.fetch_add(1);
            throw std::runtime_error{"key lookup failed"};
        };

        WHEN("they are run")
        {
            // Before the fix, two throws used up both slots and the third acquire
            // waited forever: this call would never return.
            THEN("the failure is rethrown instead of waiting forever, after every task has started")
            {
                REQUIRE_THROWS_AS(merovingian::core::run_bounded_parallel(6U, 2U, throwing), std::runtime_error);
                REQUIRE(started.load() == 6);
            }
        }
    }

    GIVEN("five tasks where only the first throws")
    {
        auto finished = std::atomic<int>{0};
        auto finished_when_rethrown = std::atomic<int>{-1};
        auto const mixed = [&](std::size_t const index) {
            if (index == 0U)
            {
                throw std::runtime_error{"first lookup failed"};
            }
            std::this_thread::sleep_for(std::chrono::milliseconds{20});
            finished.fetch_add(1);
        };

        WHEN("they are run")
        {
            try
            {
                merovingian::core::run_bounded_parallel(5U, 2U, mixed);
            }
            catch (std::runtime_error const&)
            {
                finished_when_rethrown.store(finished.load());
            }

            THEN("the failure surfaces only once every other task has finished")
            {
                REQUIRE(finished_when_rethrown.load() == 4);
            }
        }
    }
}
