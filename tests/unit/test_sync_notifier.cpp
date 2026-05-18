// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/sync/sync_notifier.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <thread>

SCENARIO("SyncNotifier returns immediately when the stream id has already advanced",
         "[sync][notifier]")
{
    GIVEN("a notifier published past the caller's since-token")
    {
        auto notifier = merovingian::sync::SyncNotifier{};
        notifier.publish(5U);

        WHEN("a sync call waits with since=3 and a long timeout")
        {
            auto const woke = notifier.wait_for_change(3U, std::chrono::milliseconds{500});

            THEN("wait returns true without blocking on the timeout")
            {
                REQUIRE(woke);
                REQUIRE(notifier.current_stream_id() == 5U);
            }
        }
    }
}

SCENARIO("SyncNotifier blocks until publish bumps the stream id", "[sync][notifier]")
{
    GIVEN("a fresh notifier at stream id 0 and a sync waiter parked at since=0")
    {
        auto notifier = merovingian::sync::SyncNotifier{};
        auto woke = std::atomic<bool>{false};
        auto waiter = std::thread{[&] {
            woke.store(notifier.wait_for_change(0U, std::chrono::milliseconds{2000}));
        }};

        WHEN("a producer publishes id=1")
        {
            std::this_thread::sleep_for(std::chrono::milliseconds{20});
            notifier.publish(1U);
            waiter.join();

            THEN("the waiter wakes and reports the change")
            {
                REQUIRE(woke.load());
                REQUIRE(notifier.current_stream_id() == 1U);
            }
        }
    }
}

SCENARIO("SyncNotifier wait returns false on timeout when nothing publishes", "[sync][notifier]")
{
    GIVEN("a notifier at id 0 with no pending publish")
    {
        auto notifier = merovingian::sync::SyncNotifier{};

        WHEN("a sync call waits with a tiny timeout")
        {
            auto const woke = notifier.wait_for_change(0U, std::chrono::milliseconds{20});

            THEN("wait reports timeout")
            {
                REQUIRE_FALSE(woke);
            }
        }
    }
}
