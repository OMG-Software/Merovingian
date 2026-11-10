// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/database/PersistentMembership.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/homeserver/RoomService.hpp"
#include "merovingian/sync/LongPollStep.hpp"
#include "merovingian/sync/SyncNotifier.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
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

using merovingian::sync::LongPollStep;
using merovingian::sync::SyncNotifier;

// Parks a waiter for `user` on a thread; the result is read after join() on the main thread only.
class ParkedWaiter final
{
public:
    ParkedWaiter(SyncNotifier& notifier, std::string user, std::size_t expected_waiting)
        : thread_{[this, &notifier, user = std::move(user)] {
            auto const cursor = notifier.observe(user);
            woke_.store(notifier.wait_for_change(cursor, std::chrono::seconds{60}));
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

constexpr auto alice = "@alice:example.org";
constexpr auto bob = "@bob:example.org";

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
                    auto waiter = ParkedWaiter{notifier, alice, 1U};

                    auto const bobs = users({bob});
                    notifier.publish(1U, 0U, bobs);
                    REQUIRE(notifier.signals_sent() == 0U);
                    REQUIRE(notifier.waiting() == 1U);

                    auto const alices = users({bob, alice});
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
                    auto waiter = ParkedWaiter{notifier, alice, 1U};

                    notifier.publish(1U, 0U);
                    REQUIRE(waiter.join());
                    REQUIRE(notifier.signals_sent() == 1U);
                }
            }
        }
    }

    GIVEN("a waiter that named no user and a waiter for bob")
    {
        auto notifier = SyncNotifier{};
        auto anyone = std::atomic<bool>{false};
        auto anyone_thread = std::thread{[&] {
            anyone.store(notifier.wait_for_change(0U, 0U, std::chrono::seconds{60}));
        }};
        while (notifier.waiting() < 1U)
        {
            std::this_thread::yield();
        }
        auto bobs_waiter = ParkedWaiter{notifier, bob, 2U};

        WHEN("an event scoped to bob is published")
        {
            auto const bobs = users({bob});
            notifier.publish(1U, 0U, bobs);

            THEN("both wake, the one with no user as every waiter always did")
            {
                anyone_thread.join();
                REQUIRE(anyone.load());
                REQUIRE(bobs_waiter.join());
                REQUIRE(notifier.signals_sent() == 2U);
            }
        }
    }
}

// ADR-0437: a cursor is the user's place in the notifier's history, kept across slices.
SCENARIO("SyncNotifier cursors see what was published between two waits", "[sync][notifier][scoped][cursor]")
{
    GIVEN("a cursor taken for alice")
    {
        auto notifier = SyncNotifier{};
        auto const cursor = notifier.observe(alice);

        WHEN("publishes scoped to bob move the positions, with no wait in progress")
        {
            auto const bobs = users({bob});
            notifier.publish(5U, 5U, bobs);
            notifier.publish(6U, 6U, bobs);

            THEN("alice's wait does not return, whatever the positions say")
            {
                REQUIRE_FALSE(notifier.wait_for_change(cursor, std::chrono::milliseconds{0}));
            }
        }
        WHEN("a publish scoped to alice lands between two waits")
        {
            auto const alices = users({alice});
            notifier.publish(1U, 0U, alices);

            THEN("her next wait returns true at once")
            {
                REQUIRE(notifier.wait_for_change(cursor, std::chrono::milliseconds{0}));
            }
            THEN("a cursor taken afterwards starts from there")
            {
                auto const later = notifier.observe(alice);
                REQUIRE_FALSE(notifier.wait_for_change(later, std::chrono::milliseconds{0}));
            }
        }
        WHEN("a broadcast lands between two waits")
        {
            notifier.publish(1U, 0U);

            THEN("her next wait returns true at once")
            {
                REQUIRE(notifier.wait_for_change(cursor, std::chrono::milliseconds{0}));
            }
        }
    }

    GIVEN("a user whose generation is kept after the last waiter leaves")
    {
        auto notifier = SyncNotifier{};
        auto const first = notifier.observe(alice);
        REQUIRE_FALSE(notifier.wait_for_change(first, std::chrono::milliseconds{1}));

        WHEN("a publish scoped to her lands while nobody waits")
        {
            auto const alices = users({alice});
            notifier.publish(1U, 0U, alices);

            THEN("the cursor she held earlier sees it")
            {
                REQUIRE(notifier.wait_for_change(first, std::chrono::milliseconds{0}));
            }
        }
    }
}

namespace
{

// Counts what a long-poll did, from atomics the main thread reads. The long-poll runs on a thread of its own
// and asserts nothing.
struct PollProbe final
{
    std::atomic<int> reruns{0};
    std::atomic<int> idle_slices{0};
    std::atomic<bool> complete{false};
    std::atomic<bool> gone{false};
};

// Runs long_poll_wait for `user` from `since` on a thread, with 2 ms slices and a 60 s deadline.
template <typename OnRerun, typename OnIdle>
class PollThread final
{
public:
    PollThread(SyncNotifier& notifier, PollProbe& probe, std::string user, std::uint64_t since_ordering,
               OnRerun on_rerun, OnIdle on_idle)
        : thread_{[&notifier, &probe, user = std::move(user), since_ordering, on_rerun = std::move(on_rerun),
                   on_idle = std::move(on_idle)]() mutable {
            auto const result = merovingian::sync::long_poll_wait(
                notifier, user, since_ordering, 0U, std::chrono::steady_clock::now() + std::chrono::seconds{60},
                std::chrono::milliseconds{2},
                []() {
                    return true;
                },
                [&]() {
                    auto const count = ++probe.reruns;
                    return on_rerun(count);
                },
                [&]() {
                    ++probe.idle_slices;
                    return on_idle(probe.idle_slices.load());
                });
            probe.complete.store(result.dispatched);
            probe.gone.store(result.client_gone);
        }}
    {
    }
    PollThread(PollThread const&) = delete;
    auto operator=(PollThread const&) -> PollThread& = delete;
    ~PollThread()
    {
        if (thread_.joinable())
        {
            thread_.join();
        }
    }
    auto join() -> void
    {
        thread_.join();
    }

private:
    std::thread thread_;
};

[[nodiscard]] auto done(std::uint64_t since_ordering = 0U) -> LongPollStep
{
    return {true, since_ordering, 0U};
}
[[nodiscard]] auto pending(std::uint64_t since_ordering) -> LongPollStep
{
    return {false, since_ordering, 0U};
}

} // namespace

// ADR-0437: the long-poll reruns the sync for a change that concerns the user, not once per slice.
SCENARIO("A long-poll reruns its sync only for changes that concern its user", "[sync][notifier][scoped][long-poll]")
{
    GIVEN("a long-poll for alice whose positions are overtaken by publishes scoped to bob")
    {
        WHEN("several slices pass")
        {
            THEN("the sync is not rerun, and is rerun once for a publish scoped to alice")
            {
                for (auto round = 0; round < 20; ++round)
                {
                    // Every round builds a fresh notifier and poll thread and repeats the race 20 times, since a
                    // wake-up that is missed only shows up under some interleavings.
                    auto notifier = SyncNotifier{};
                    auto probe = PollProbe{};
                    auto poll = PollThread{notifier,
                                           probe,
                                           alice,
                                           0U,
                                           [](int) {
                                               return done();
                                           },
                                           [](int) {
                                               return true;
                                           }};
                    // Wait for the poll to complete a slice, so the publishes below happen while it is asleep
                    // rather than before it starts.
                    while (probe.idle_slices.load() < 1)
                    {
                        std::this_thread::yield();
                    }
                    // Both stream positions advance, but the publish is scoped to bob, so alice's poll must stay
                    // asleep.
                    auto const bobs = users({bob});
                    notifier.publish(7U, 7U, bobs);
                    auto const seen = probe.idle_slices.load();
                    // Three further slices pass, each a chance for an unscoped wake-up. The rerun count must still
                    // be zero.
                    while (probe.idle_slices.load() < seen + 3)
                    {
                        std::this_thread::yield();
                    }
                    REQUIRE(probe.reruns.load() == 0);

                    // A publish scoped to alice is the only thing that may rerun the sync, and it does so once.
                    auto const alices = users({alice});
                    notifier.publish(8U, 8U, alices);
                    poll.join();
                    REQUIRE(probe.reruns.load() == 1);
                    REQUIRE(probe.complete.load());
                }
            }
        }
    }

    GIVEN("a publish scoped to alice that lands between two slices")
    {
        WHEN("the first slice ends")
        {
            THEN("the next wait sees it and the sync is rerun")
            {
                for (auto round = 0; round < 20; ++round)
                {
                    auto notifier = SyncNotifier{};
                    auto probe = PollProbe{};
                    // The publish is made from inside the idle check, between one slice ending and the next wait.
                    // The cursor taken at the start of the wait must still see it.
                    auto const alices = users({alice});
                    auto poll = PollThread{notifier,
                                           probe,
                                           alice,
                                           0U,
                                           [](int) {
                                               return done();
                                           },
                                           [&notifier, &alices](int slices) {
                                               if (slices == 1)
                                               {
                                                   notifier.publish(1U, 0U, alices);
                                               }
                                               return true;
                                           }};
                    poll.join();
                    REQUIRE(probe.reruns.load() == 1);
                    REQUIRE(probe.complete.load());
                }
            }
        }
    }

    GIVEN("a broadcast that lands between two slices")
    {
        WHEN("the first slice ends")
        {
            THEN("the next wait sees it and the sync is rerun")
            {
                for (auto round = 0; round < 20; ++round)
                {
                    auto notifier = SyncNotifier{};
                    auto probe = PollProbe{};
                    // The same race with a broadcast, which names no user and so wakes every poll.
                    auto poll = PollThread{notifier,
                                           probe,
                                           alice,
                                           0U,
                                           [](int) {
                                               return done();
                                           },
                                           [&notifier](int slices) {
                                               if (slices == 1)
                                               {
                                                   notifier.publish(1U, 0U);
                                               }
                                               return true;
                                           }};
                    poll.join();
                    REQUIRE(probe.reruns.load() == 1);
                    REQUIRE(probe.complete.load());
                }
            }
        }
    }

    GIVEN("a publish scoped to alice that lands after the cursor and before the rerun's snapshot")
    {
        WHEN("the stream was already ahead of the long-poll's position, so it reruns at once")
        {
            THEN("one extra rerun follows and nothing is lost")
            {
                for (auto round = 0; round < 20; ++round)
                {
                    auto notifier = SyncNotifier{};
                    // The stream is already ahead of the poll's position, so the first sync runs at once. The
                    // publish for bob moves nothing for alice.
                    auto const bobs = users({bob});
                    notifier.publish(1U, 0U, bobs);
                    auto probe = PollProbe{};
                    auto const alices = users({alice});
                    // The first rerun reports the sync as pending at position 2, as if it had not yet caught up.
                    auto poll = PollThread{notifier,
                                           probe,
                                           alice,
                                           0U,
                                           [&notifier, &alices](int count) {
                                               if (count == 1)
                                               {
                                                   // Lands between observe() and this rerun's snapshot.
                                                   notifier.publish(2U, 0U, alices);
                                                   return pending(2U);
                                               }
                                               return done();
                                           },
                                           [](int) {
                                               return true;
                                           }};
                    poll.join();
                    REQUIRE(probe.reruns.load() == 2);
                    REQUIRE(probe.complete.load());
                }
            }
        }
    }

    GIVEN("a long-poll that named no user")
    {
        WHEN("any publish happens")
        {
            THEN("it reruns, as every long-poll once did")
            {
                // An empty user name stands for a poll that cannot be scoped, which every publish wakes.
                auto notifier = SyncNotifier{};
                auto probe = PollProbe{};
                auto poll = PollThread{notifier,
                                       probe,
                                       "",
                                       0U,
                                       [](int) {
                                           return done();
                                       },
                                       [](int) {
                                           return true;
                                       }};
                while (probe.idle_slices.load() < 1)
                {
                    std::this_thread::yield();
                }
                auto const bobs = users({bob});
                notifier.publish(1U, 0U, bobs);
                poll.join();
                REQUIRE(probe.reruns.load() == 1);
            }
        }
    }

    GIVEN("a long-poll whose idle check finds the client gone")
    {
        WHEN("a slice ends")
        {
            THEN("it stops without rerunning")
            {
                // The idle check returns false, the way a disconnected client is reported, so the poll gives up
                // after its first slice.
                auto notifier = SyncNotifier{};
                auto probe = PollProbe{};
                auto poll = PollThread{notifier,
                                       probe,
                                       alice,
                                       0U,
                                       [](int) {
                                           return done();
                                       },
                                       [](int) {
                                           return false;
                                       }};
                poll.join();
                REQUIRE(probe.gone.load());
                REQUIRE(probe.reruns.load() == 0);
            }
        }
    }
}

// ADR-0437: the users an event in a room is published to.
SCENARIO("A room event's sync audience is its joined and invited members, its sender and the user it is about",
         "[sync][notifier][scoped][audience]")
{
    GIVEN("a room with joined, invited, knocking, left and banned users, written through the store")
    {
        auto store = merovingian::database::PersistentStore{};
        auto const write = [&store](char const* room, char const* user, char const* membership, std::uint64_t order) {
            REQUIRE(merovingian::database::store_membership_projection(store, room, {user, membership, order, {}}));
        };
        write("!room:example.org", "@joined:example.org", "join", 1U);
        write("!room:example.org", "@invited:example.org", "invite", 2U);
        write("!room:example.org", "@knocking:example.org", "knock", 3U);
        write("!room:example.org", "@left:example.org", "leave", 4U);
        write("!room:example.org", "@banned:example.org", "ban", 5U);
        write("!other:example.org", "@elsewhere:example.org", "join", 6U);
        // An invitee who joins is one row that changes in place.
        write("!room:example.org", "@invited:example.org", "join", 7U);
        // A deleted row is gone from the room.
        write("!room:example.org", "@forgotten:example.org", "join", 8U);
        REQUIRE(merovingian::database::delete_membership(store, "!room:example.org", "@forgotten:example.org"));

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
            THEN("the per-room index is in step with the rows and answers without a scan of other rooms")
            {
                REQUIRE(store.membership_indexed_rows == store.memberships.size());
                auto visited = std::vector<std::string>{};
                merovingian::database::for_each_room_membership_row(
                    store, "!other:example.org", [&visited](merovingian::database::PersistentMembership const& row) {
                        visited.push_back(row.room_id + row.user_id);
                    });
                REQUIRE(visited == std::vector<std::string>{"!other:example.org@elsewhere:example.org"});
            }
        }
        WHEN("rows are added behind the store's back")
        {
            store.memberships.push_back({"!room:example.org", "@sneaky:example.org", "join", 9U});
            auto const audience = merovingian::homeserver::sync_audience_of_room(store, "!room:example.org", {});

            THEN("the audience still holds them, by falling back to a scan")
            {
                REQUIRE(std::ranges::find(audience, "@sneaky:example.org") != audience.end());
            }
        }
    }
}

// ADR-0437: a publish moves generations whether or not the positions advanced. Every caller publishes the visible
// position read at publish time, so one writer's publish can carry the position of another writer's event.
SCENARIO("A publish that does not advance the positions still wakes the users it names",
         "[scoped-federation][notifier][scoped]")
{
    GIVEN("the positions raised to 5 by a publish scoped to bob")
    {
        auto notifier = SyncNotifier{};
        auto const bobs = users({bob});
        notifier.publish(5U, 5U, bobs);
        auto const cursor = notifier.observe(alice);
        auto const bobs_cursor = notifier.observe(bob);

        WHEN("a publish at the same positions is scoped to alice")
        {
            auto const alices = users({alice});
            notifier.publish(5U, 5U, alices);

            THEN("alice's cursor moved, and bob's did not")
            {
                REQUIRE(notifier.wait_for_change(cursor, std::chrono::milliseconds{0}));
                REQUIRE_FALSE(notifier.wait_for_change(bobs_cursor, std::chrono::milliseconds{0}));
            }
        }
        WHEN("a publish at the same positions names no scope")
        {
            notifier.publish(5U, 5U);

            THEN("every cursor moved")
            {
                REQUIRE(notifier.wait_for_change(cursor, std::chrono::milliseconds{0}));
                REQUIRE(notifier.wait_for_change(bobs_cursor, std::chrono::milliseconds{0}));
            }
        }
        WHEN("a publish at lower positions is scoped to alice")
        {
            auto const alices = users({alice});
            notifier.publish(2U, 2U, alices);

            THEN("alice's cursor moved, though the positions stayed")
            {
                REQUIRE(notifier.wait_for_change(cursor, std::chrono::milliseconds{0}));
                REQUIRE_FALSE(notifier.wait_for_change(5U, 5U, std::chrono::milliseconds{0}));
            }
        }
    }

    GIVEN("a waiter for alice parked, repeated to catch a race")
    {
        WHEN("a no-advance publish scoped to alice is made")
        {
            THEN("she wakes")
            {
                for (auto round = 0; round < 200; ++round)
                {
                    auto notifier = SyncNotifier{};
                    auto const bobs = users({bob});
                    notifier.publish(5U, 5U, bobs);
                    auto waiter = ParkedWaiter{notifier, alice, 1U};

                    auto const alices = users({alice});
                    notifier.publish(5U, 5U, alices);
                    REQUIRE(waiter.join());
                }
            }
        }
    }
}

// ADR-0437: a scope that is present and empty moves the positions and wakes no user.
SCENARIO("A publish with an empty scope moves the positions and wakes no user", "[scoped-federation][notifier][scoped]")
{
    GIVEN("a waiter for alice parked and a waiter that named no user")
    {
        auto notifier = SyncNotifier{};
        auto anyone = std::atomic<bool>{false};
        auto anyone_thread = std::thread{[&] {
            anyone.store(notifier.wait_for_change(0U, 0U, std::chrono::seconds{60}));
        }};
        while (notifier.waiting() < 1U)
        {
            std::this_thread::yield();
        }
        auto waiter = ParkedWaiter{notifier, alice, 2U};
        auto const cursor = notifier.observe(alice);

        WHEN("a publish names an empty scope")
        {
            auto const nobody = std::vector<std::string>{};
            notifier.publish(1U, 0U, nobody);
            anyone_thread.join();

            THEN("the position waiter wakes, alice's cursor does not move and she is not signalled")
            {
                REQUIRE(anyone.load());
                REQUIRE_FALSE(notifier.wait_for_change(cursor, std::chrono::milliseconds{0}));
                REQUIRE(notifier.signals_sent() == 1U);
                REQUIRE(notifier.waiting() == 1U);
                // Alice still wakes for a publish that concerns her.
                auto const alices = users({alice});
                notifier.publish(2U, 0U, alices);
                REQUIRE(waiter.join());
            }
        }
    }
}
