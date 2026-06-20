// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/sync/sync_notifier.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <mutex>
#include <thread>

SCENARIO("SyncNotifier returns immediately when the sync stream id has already advanced",
         "[sync][notifier]")
{
    GIVEN("a notifier published past the caller's since-token")
    {
        auto notifier = merovingian::sync::SyncNotifier{};
        notifier.publish(0U, 5U);

        WHEN("a sync call waits with since_stream_ordering=0 and since_sync_stream_id=3")
        {
            auto const woke =
                notifier.wait_for_change(0U, 3U, std::chrono::milliseconds{500});

            THEN("wait returns true without blocking on the timeout")
            {
                REQUIRE(woke);
                REQUIRE(notifier.current_sync_stream_id() == 5U);
            }
        }
    }
}

SCENARIO("SyncNotifier returns immediately when stream_ordering has advanced",
         "[sync][notifier]")
{
    GIVEN("a notifier with stream_ordering=10 and sync_stream_id=0")
    {
        auto notifier = merovingian::sync::SyncNotifier{};
        notifier.publish(10U, 0U);

        WHEN("a sync call waits with since_stream_ordering=5")
        {
            auto const woke =
                notifier.wait_for_change(5U, 0U, std::chrono::milliseconds{500});

            THEN("wait returns true because timeline events are available")
            {
                REQUIRE(woke);
            }
        }
    }
}

SCENARIO("SyncNotifier blocks until publish bumps either counter", "[sync][notifier]")
{
    GIVEN("a fresh notifier at counters 0,0 and a sync waiter parked at since=0,0")
    {
        auto notifier = merovingian::sync::SyncNotifier{};
        auto woke = std::atomic<bool>{false};
        auto waiter = std::thread{[&] {
            woke.store(notifier.wait_for_change(0U, 0U, std::chrono::milliseconds{2000}));
        }};

        WHEN("a producer publishes sync_stream_id=1")
        {
            std::this_thread::sleep_for(std::chrono::milliseconds{20});
            notifier.publish(0U, 1U);
            waiter.join();

            THEN("the waiter wakes and reports the change")
            {
                REQUIRE(woke.load());
                REQUIRE(notifier.current_sync_stream_id() == 1U);
            }
        }
    }
}

SCENARIO("SyncNotifier wakes on stream_ordering advance while waiting", "[sync][notifier]")
{
    GIVEN("a fresh notifier and a waiter parked at since_stream_ordering=0")
    {
        auto notifier = merovingian::sync::SyncNotifier{};
        auto woke = std::atomic<bool>{false};
        auto waiter = std::thread{[&] {
            woke.store(notifier.wait_for_change(0U, 0U, std::chrono::milliseconds{2000}));
        }};

        WHEN("a producer publishes stream_ordering=7 (timeline event)")
        {
            std::this_thread::sleep_for(std::chrono::milliseconds{20});
            notifier.publish(7U, 0U);
            waiter.join();

            THEN("the waiter wakes because a timeline event arrived")
            {
                REQUIRE(woke.load());
            }
        }
    }
}

SCENARIO("SyncNotifier wait returns false on timeout when nothing publishes", "[sync][notifier]")
{
    GIVEN("a notifier at counters 0,0 with no pending publish")
    {
        auto notifier = merovingian::sync::SyncNotifier{};

        WHEN("a sync call waits with a tiny timeout")
        {
            auto const woke = notifier.wait_for_change(0U, 0U, std::chrono::milliseconds{20});

            THEN("wait reports timeout")
            {
                REQUIRE_FALSE(woke);
            }
        }
    }
}

SCENARIO("An external mutex is releasable while a sync wait is parked",
         "[sync][notifier][lock-release]")
{
    GIVEN("a mutex a client holds across a sync wait and a SyncNotifier at counters 0,0")
    {
        auto notifier = merovingian::sync::SyncNotifier{};
        auto mtx = std::timed_mutex{};

        WHEN("a waiter thread unlocks the mutex, calls wait_for_change, then re-locks")
        {
            auto waiter_done = std::atomic<bool>{false};
            auto waiter = std::thread{[&] {
                // The full lock lifecycle stays on this thread: a
                // std::timed_mutex must be unlocked by the same thread that
                // locked it, so acquiring it here (not on the test thread)
                // keeps lock/unlock/re-lock ownership consistent.
                auto lock = std::unique_lock<std::timed_mutex>{mtx};
                lock.unlock();
                std::ignore = notifier.wait_for_change(0U, 0U, std::chrono::milliseconds{2000});
                lock.lock();
                waiter_done.store(true);
            }};

            // Give the waiter a moment to enter the condition_variable wait.
            std::this_thread::sleep_for(std::chrono::milliseconds{50});

            THEN("another thread can acquire the mutex while the waiter is parked")
            {
                auto acquired = std::atomic<bool>{false};
                auto probe = std::thread{[&] {
                    auto probe_lock = std::unique_lock<std::timed_mutex>{mtx, std::defer_lock};
                    acquired.store(probe_lock.try_lock_for(std::chrono::milliseconds{500}));
                    if (acquired.load())
                    {
                        probe_lock.unlock();
                    }
                }};
                probe.join();

                // Wake the waiter so the test doesn't hang.
                notifier.publish(1U, 1U);
                waiter.join();

                REQUIRE(acquired.load());
                REQUIRE(waiter_done.load());
            }
        }
    }
}

SCENARIO("A single publish wakes all concurrent waiters simultaneously", "[sync][notifier][concurrency]")
{
    // This scenario validates the mechanism that prevents thread-pool starvation:
    // many sync-pool threads may be parked waiting for new events; a single
    // federation publish must wake ALL of them, not just one.
    GIVEN("eight threads parked in wait_for_change at since counters 0,0")
    {
        constexpr std::size_t waiter_count = 8U;
        auto notifier = merovingian::sync::SyncNotifier{};
        auto woke = std::array<std::atomic<bool>, waiter_count>{};
        for (auto& flag : woke)
        {
            flag.store(false);
        }
        auto ready = std::atomic<std::size_t>{0U};

        auto waiters = std::vector<std::thread>{};
        waiters.reserve(waiter_count);
        for (std::size_t i = 0U; i < waiter_count; ++i)
        {
            waiters.emplace_back([&notifier, &woke, &ready, i] {
                ready.fetch_add(1U, std::memory_order_release);
                woke[i].store(notifier.wait_for_change(0U, 0U, std::chrono::milliseconds{3000}),
                              std::memory_order_release);
            });
        }

        WHEN("publish fires once after all threads have entered the wait")
        {
            // Spin until all threads are waiting so the publish races against none of them.
            while (ready.load(std::memory_order_acquire) < waiter_count)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds{5});
            }
            std::this_thread::sleep_for(std::chrono::milliseconds{20});
            notifier.publish(0U, 1U);

            for (auto& t : waiters)
            {
                t.join();
            }

            THEN("every waiter wakes and reports the change")
            {
                for (std::size_t i = 0U; i < waiter_count; ++i)
                {
                    REQUIRE(woke[i].load());
                }
            }
        }
    }
}

SCENARIO("A to-device publish does not unblock a waiter whose since-token already covers it",
         "[sync][notifier]")
{
    // Guards against a regression where publish() could skip notify_all() when
    // the new sync_stream_id is not strictly greater than the stored value, while
    // a waiter's since token is already at or above the stored value.
    GIVEN("a notifier already at sync_stream_id=5, a waiter parked at since=5")
    {
        auto notifier = merovingian::sync::SyncNotifier{};
        notifier.publish(0U, 5U);

        WHEN("wait_for_change is called with since_sync_stream_id=5 and a short timeout")
        {
            auto const woke = notifier.wait_for_change(0U, 5U, std::chrono::milliseconds{40});

            THEN("the wait times out because no new data is available past since=5")
            {
                REQUIRE_FALSE(woke);
            }
        }
    }
}