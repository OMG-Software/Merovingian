// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/room_service.hpp"
#include "merovingian/sync/sync_notifier.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

SCENARIO("SyncNotifier returns immediately when the sync stream id has already advanced", "[sync][notifier]")
{
    GIVEN("a notifier published past the caller's since-token")
    {
        auto notifier = merovingian::sync::SyncNotifier{};
        notifier.publish(0U, 5U);

        WHEN("a sync call waits with since_stream_ordering=0 and since_sync_stream_id=3")
        {
            auto const woke = notifier.wait_for_change(0U, 3U, std::chrono::milliseconds{500});

            THEN("wait returns true without blocking on the timeout")
            {
                REQUIRE(woke);
                REQUIRE(notifier.current_sync_stream_id() == 5U);
            }
        }
    }
}

SCENARIO("SyncNotifier returns immediately when stream_ordering has advanced", "[sync][notifier]")
{
    GIVEN("a notifier with stream_ordering=10 and sync_stream_id=0")
    {
        auto notifier = merovingian::sync::SyncNotifier{};
        notifier.publish(10U, 0U);

        WHEN("a sync call waits with since_stream_ordering=5")
        {
            auto const woke = notifier.wait_for_change(5U, 0U, std::chrono::milliseconds{500});

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

SCENARIO("An external mutex is releasable while a sync wait is parked", "[sync][notifier][lock-release]")
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

SCENARIO("A to-device publish does not unblock a waiter whose since-token already covers it", "[sync][notifier]")
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
SCENARIO("SyncNotifier counts the callers blocked in a wait", "[sync][notifier][concurrency]")
{
    GIVEN("a notifier with nothing published past the since-values")
    {
        auto notifier = merovingian::sync::SyncNotifier{};

        WHEN("one caller waits on another thread until a publish wakes it")
        {
            auto woke = std::atomic<bool>{false};
            auto waiter = std::thread{[&notifier, &woke] {
                woke.store(notifier.wait_for_change(0U, 0U, std::chrono::seconds{10}));
            }};
            auto const deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
            while (notifier.waiting() == 0U && std::chrono::steady_clock::now() < deadline)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds{1});
            }
            auto const while_waiting = notifier.waiting();
            notifier.publish(1U, 0U);
            waiter.join();

            THEN("it is counted while blocked and no longer once it has returned")
            {
                REQUIRE(while_waiting == 1U);
                REQUIRE(woke.load());
                REQUIRE(notifier.waiting() == 0U);
            }
        }

        WHEN("a caller's wait returns at once because the counter already advanced")
        {
            notifier.publish(1U, 0U);
            auto const changed = notifier.wait_for_change(0U, 0U, std::chrono::seconds{10});

            THEN("it was never counted as waiting")
            {
                REQUIRE(changed);
                REQUIRE(notifier.waiting() == 0U);
            }
        }
    }
}

namespace
{

using merovingian::sync::SyncNotifier;

// Parks a waiter for `user` on a thread; the result is read after join() on the main thread only.
class ParkedWaiter final
{
public:
    ParkedWaiter(SyncNotifier& notifier, std::string user, std::size_t expected_waiting)
        : thread_{[this, &notifier, user = std::move(user)] {
            woke_.store(notifier.wait_for_change(0U, 0U, std::chrono::seconds{60}, user));
        }}
    {
        // Wait for it to park, by yielding rather than by sleeping.
        while (notifier.waiting() < expected_waiting)
        {
            std::this_thread::yield();
        }
    }
    ParkedWaiter(ParkedWaiter const&) = delete;
    auto operator=(ParkedWaiter const&) -> ParkedWaiter& = delete;
    ~ParkedWaiter()
    {
        if (thread_.joinable())
        {
            thread_.join();
        }
    }
    [[nodiscard]] auto join() -> bool
    {
        thread_.join();
        return woke_.load();
    }

private:
    std::atomic<bool> woke_{false};
    std::thread thread_;
};

[[nodiscard]] auto users(std::vector<std::string> names) -> std::vector<std::string>
{
    return names;
}

} // namespace

// ADR-0437: a long-poll is woken for its own user, not for every event on the server.
SCENARIO("SyncNotifier wakes a waiter only for publishes that concern its user", "[sync][notifier][scoped]")
{
    GIVEN("a waiter for alice parked on the notifier, repeated to catch a race")
    {
        WHEN("an event scoped to bob is published, then one scoped to alice")
        {
            THEN("alice is signalled by the second only, and wakes with the change")
            {
                for (auto round = 0; round < 200; ++round)
                {
                    auto notifier = SyncNotifier{};
                    auto waiter = ParkedWaiter{notifier, "@alice:example.org", 1U};

                    auto const bobs = users({"@bob:example.org"});
                    notifier.publish(1U, 0U, bobs);
                    REQUIRE(notifier.signals_sent() == 0U);
                    REQUIRE(notifier.waiting() == 1U);

                    auto const alices = users({"@bob:example.org", "@alice:example.org"});
                    notifier.publish(2U, 0U, alices);
                    REQUIRE(waiter.join());
                    REQUIRE(notifier.signals_sent() == 1U);
                }
            }
        }
    }

    GIVEN("a waiter for alice and a publish that names no scope")
    {
        WHEN("the publish is made")
        {
            THEN("alice wakes")
            {
                for (auto round = 0; round < 200; ++round)
                {
                    auto notifier = SyncNotifier{};
                    auto waiter = ParkedWaiter{notifier, "@alice:example.org", 1U};

                    notifier.publish(1U, 0U);
                    REQUIRE(waiter.join());
                    REQUIRE(notifier.signals_sent() == 1U);
                }
            }
        }
    }

    GIVEN("a waiter for alice and an invite to her, to a room she was not in")
    {
        WHEN("an event scoped to the inviter and the invitee is published")
        {
            THEN("alice wakes")
            {
                for (auto round = 0; round < 200; ++round)
                {
                    auto notifier = SyncNotifier{};
                    auto waiter = ParkedWaiter{notifier, "@alice:example.org", 1U};

                    auto const audience = users({"@bob:example.org", "@alice:example.org"});
                    notifier.publish(1U, 0U, audience);
                    REQUIRE(waiter.join());
                }
            }
        }
    }

    GIVEN("a waiter that named no user and a waiter for bob")
    {
        auto notifier = SyncNotifier{};
        auto anyone = ParkedWaiter{notifier, "", 1U};
        auto bob = ParkedWaiter{notifier, "@bob:example.org", 2U};

        WHEN("an event scoped to bob is published")
        {
            auto const bobs = users({"@bob:example.org"});
            notifier.publish(1U, 0U, bobs);

            THEN("both wake, the one with no user as every waiter always did")
            {
                REQUIRE(anyone.join());
                REQUIRE(bob.join());
                REQUIRE(notifier.signals_sent() == 2U);
            }
        }
    }

    GIVEN("a publish scoped to bob made before alice began to wait")
    {
        auto notifier = SyncNotifier{};
        auto const bobs = users({"@bob:example.org"});
        notifier.publish(5U, 0U, bobs);

        WHEN("alice waits from before it")
        {
            auto const woke = notifier.wait_for_change(0U, 0U, std::chrono::milliseconds{0}, "@alice:example.org");

            THEN("she is told at once, as the stream is ahead of her")
            {
                REQUIRE(woke);
            }
        }
        WHEN("alice waits from the position it reached")
        {
            auto const woke = notifier.wait_for_change(5U, 0U, std::chrono::milliseconds{0}, "@alice:example.org");

            THEN("nothing is pending")
            {
                REQUIRE_FALSE(woke);
            }
        }
    }

    GIVEN("a waiter racing a publish scoped to it")
    {
        WHEN("the publish may land before, or after, the waiter parks")
        {
            THEN("the change is never lost")
            {
                for (auto round = 0; round < 200; ++round)
                {
                    auto notifier = SyncNotifier{};
                    auto woke = std::atomic<bool>{false};
                    auto waiter = std::thread{[&] {
                        woke.store(notifier.wait_for_change(0U, 0U, std::chrono::seconds{60}, "@alice:example.org"));
                    }};
                    auto const alices = users({"@alice:example.org"});

                    notifier.publish(1U, 0U, alices);
                    waiter.join();
                    REQUIRE(woke.load());
                }
            }
        }
    }
}

// ADR-0437: the users an event in a room is published to.
SCENARIO("A room event's sync audience is its joined and invited members, its sender and the user it is about",
         "[sync][notifier][scoped]")
{
    GIVEN("a room with joined, invited, knocking, left and banned users")
    {
        auto store = merovingian::database::PersistentStore{};
        store.memberships.push_back({"!room:example.org", "@joined:example.org", "join", 1U});
        store.memberships.push_back({"!room:example.org", "@invited:example.org", "invite", 2U});
        store.memberships.push_back({"!room:example.org", "@knocking:example.org", "knock", 3U});
        store.memberships.push_back({"!room:example.org", "@left:example.org", "leave", 4U});
        store.memberships.push_back({"!room:example.org", "@banned:example.org", "ban", 5U});
        store.memberships.push_back({"!other:example.org", "@elsewhere:example.org", "join", 6U});

        WHEN("the audience of an event sent by a member who kicked another is built")
        {
            auto const audience = merovingian::homeserver::sync_audience_of_room(
                store, "!room:example.org", {"@joined:example.org", "@kicked:example.org", ""});

            THEN("it holds each joined and invited user once, the sender and the removed user, and no one else")
            {
                auto sorted = audience;
                std::ranges::sort(sorted);
                REQUIRE(sorted ==
                        std::vector<std::string>{"@invited:example.org", "@joined:example.org", "@kicked:example.org"});
            }
        }
    }
}
