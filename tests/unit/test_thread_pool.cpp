// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/net/thread_pool.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>

SCENARIO("ThreadPool executes submitted work items", "[net][thread_pool]")
{
    GIVEN("a pool with 2 workers")
    {
        auto pool = merovingian::net::ThreadPool{2U};
        auto executed = std::atomic<bool>{false};

        WHEN("a work item is submitted")
        {
            REQUIRE(pool.submit([&] { executed.store(true); }));
            std::this_thread::sleep_for(std::chrono::milliseconds{100});

            THEN("the work item executes")
            {
                REQUIRE(executed.load());
            }
        }
    }
}

SCENARIO("ThreadPool processes multiple work items concurrently", "[net][thread_pool]")
{
    GIVEN("a pool with 4 workers")
    {
        auto pool = merovingian::net::ThreadPool{4U};
        auto counter = std::atomic<std::size_t>{0U};

        WHEN("8 work items are submitted")
        {
            for (auto i = std::size_t{0U}; i < 8U; ++i)
            {
                REQUIRE(pool.submit([&] { counter.fetch_add(1U); }));
            }
            std::this_thread::sleep_for(std::chrono::milliseconds{200});

            THEN("all items complete")
            {
                REQUIRE(counter.load() == 8U);
            }
        }
    }
}

SCENARIO("ThreadPool request_stop prevents new submissions", "[net][thread_pool]")
{
    GIVEN("a running pool")
    {
        auto pool = merovingian::net::ThreadPool{2U};
        auto counter = std::atomic<std::size_t>{0U};

        WHEN("request_stop is called and more work is submitted")
        {
            REQUIRE(pool.submit([&] { counter.fetch_add(1U); }));
            std::this_thread::sleep_for(std::chrono::milliseconds{50});
            pool.request_stop();
            auto const before = counter.load();
            REQUIRE_FALSE(pool.submit([&] { counter.fetch_add(1U); }));
            std::this_thread::sleep_for(std::chrono::milliseconds{100});

            THEN("the post-stop submission is ignored")
            {
                REQUIRE(counter.load() == before);
            }
        }
    }
}

SCENARIO("ThreadPool running() reflects pool state", "[net][thread_pool]")
{
    GIVEN("a running pool")
    {
        auto pool = merovingian::net::ThreadPool{1U};

        WHEN("the pool has not been stopped")
        {
            THEN("running() returns true")
            {
                REQUIRE(pool.running());
            }
        }

        WHEN("request_stop() is called")
        {
            pool.request_stop();

            THEN("running() returns false")
            {
                REQUIRE_FALSE(pool.running());
            }
        }
    }
}