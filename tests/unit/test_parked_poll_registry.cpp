// SPDX-License-Identifier: GPL-3.0-or-later
//
// ADR-0569: a long-poll with nothing to return parks in the notifier's registry and gives up its thread. The
// registry's wake protocol (no lost wake-up), its cap, its deadline timer and its shutdown.
//
// Tags: [p15a] [sync] [parked-poll].

#include "../support/JoiningThreads.hpp"
#include "merovingian/sync/ParkedPoll.hpp"
#include "merovingian/sync/ParkedPollLimits.hpp"
#include "merovingian/sync/ParkedPollRegistry.hpp"
#include "merovingian/sync/SyncNotifier.hpp"
#include "merovingian/sync/WaitCursor.hpp"
#include "merovingian/sync/WakeReason.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace
{

using namespace std::chrono_literals;
using merovingian::sync::ParkedPoll;
using merovingian::sync::ParkedPollLimits;
using merovingian::sync::SyncNotifier;
using merovingian::sync::WakeReason;

// A poll that counts its own destruction, as a connection closing would.
class CountingPoll final : public ParkedPoll
{
public:
    CountingPoll(std::string poll_name, std::atomic<std::size_t>& destroyed)
        : name{std::move(poll_name)}
        , m_destroyed{destroyed}
    {
    }
    ~CountingPoll() override
    {
        ++m_destroyed;
    }
    CountingPoll(CountingPoll const&) = delete;
    auto operator=(CountingPoll const&) -> CountingPoll& = delete;
    CountingPoll(CountingPoll&&) = delete;
    auto operator=(CountingPoll&&) -> CountingPoll& = delete;

    std::string name;

private:
    std::atomic<std::size_t>& m_destroyed;
};

struct Resumed final
{
    std::string name{};
    WakeReason reason{WakeReason::published};
};

// Collects what the registry thread resumes.
class Recorder final
{
public:
    auto record(std::unique_ptr<ParkedPoll> poll, WakeReason reason) -> void
    {
        auto const* counting = dynamic_cast<CountingPoll const*>(poll.get());
        {
            auto const lock = std::lock_guard{m_mutex};
            m_items.push_back({counting != nullptr ? counting->name : std::string{}, reason});
        }
        poll.reset();
        m_changed.notify_all();
    }
    [[nodiscard]] auto wait_for(std::size_t count, std::chrono::milliseconds within) -> bool
    {
        auto lock = std::unique_lock{m_mutex};
        return m_changed.wait_for(lock, within, [&] {
            return m_items.size() >= count;
        });
    }
    [[nodiscard]] auto items() const -> std::vector<Resumed>
    {
        auto const lock = std::lock_guard{m_mutex};
        return m_items;
    }

private:
    mutable std::mutex m_mutex{};
    std::condition_variable m_changed{};
    std::vector<Resumed> m_items{};
};

[[nodiscard]] auto make_poll(std::string name, std::atomic<std::size_t>& destroyed) -> std::unique_ptr<ParkedPoll>
{
    return std::make_unique<CountingPoll>(std::move(name), destroyed);
}

auto start_registry(SyncNotifier& notifier, Recorder& recorder, ParkedPollLimits limits) -> bool
{
    return notifier.parking().start(limits, [&recorder](std::unique_ptr<ParkedPoll> poll, WakeReason reason) {
        recorder.record(std::move(poll), reason);
    });
}

} // namespace

SCENARIO("A parked poll is resumed by a publish that concerns its user and not by one that does not",
         "[p15a][sync][parked-poll]")
{
    GIVEN("two users with parked polls")
    {
        auto notifier = SyncNotifier{};
        auto recorder = Recorder{};
        auto destroyed = std::atomic<std::size_t>{0U};
        REQUIRE(start_registry(notifier, recorder, ParkedPollLimits{16U, 4U}));
        auto const far = std::chrono::steady_clock::now() + 60s;
        auto alice_poll = make_poll("alice", destroyed);
        auto bob_poll = make_poll("bob", destroyed);
        REQUIRE(notifier.park(notifier.observe("@alice:test"), far, alice_poll).has_value());
        REQUIRE(notifier.park(notifier.observe("@bob:test"), far, bob_poll).has_value());
        REQUIRE(alice_poll == nullptr);

        WHEN("a publish is scoped to alice")
        {
            auto const scope = std::vector<std::string>{"@alice:test"};
            notifier.publish(1U, 1U, std::span<std::string const>{scope});
            REQUIRE(recorder.wait_for(1U, 5s));
            std::this_thread::sleep_for(100ms);

            THEN("only alice's poll is resumed, with the published reason, and bob's stays parked")
            {
                auto const items = recorder.items();
                REQUIRE(items.size() == 1U);
                REQUIRE(items.front().name == "alice");
                REQUIRE(items.front().reason == WakeReason::published);
                REQUIRE(notifier.parking().parked() == 1U);
            }
        }

        WHEN("a publish names nobody")
        {
            notifier.publish(1U, 1U);
            REQUIRE(recorder.wait_for(2U, 5s));

            THEN("every parked poll is resumed")
            {
                REQUIRE(recorder.items().size() == 2U);
                REQUIRE(notifier.parking().parked() == 0U);
            }
        }

        WHEN("a publish is scoped to nobody at all")
        {
            notifier.publish(1U, 1U, std::span<std::string const>{});
            std::this_thread::sleep_for(150ms);

            THEN("nothing is resumed")
            {
                REQUIRE(recorder.items().empty());
                REQUIRE(notifier.parking().parked() == 2U);
            }
        }
    }
}

SCENARIO("A publish between taking the cursor and parking still resumes the poll", "[p15a][sync][parked-poll]")
{
    GIVEN("a cursor taken before a publish that lands before the park")
    {
        auto notifier = SyncNotifier{};
        auto recorder = Recorder{};
        auto destroyed = std::atomic<std::size_t>{0U};
        REQUIRE(start_registry(notifier, recorder, ParkedPollLimits{16U, 4U}));
        auto const cursor = notifier.observe("@alice:test");
        auto const scope = std::vector<std::string>{"@alice:test"};
        notifier.publish(1U, 1U, std::span<std::string const>{scope});

        WHEN("the poll then parks with that cursor")
        {
            auto poll = make_poll("late", destroyed);
            REQUIRE(notifier.park(cursor, std::chrono::steady_clock::now() + 60s, poll).has_value());

            THEN("it is resumed at once rather than waiting for its deadline")
            {
                REQUIRE(recorder.wait_for(1U, 5s));
                REQUIRE(recorder.items().front().reason == WakeReason::published);
            }
        }
    }
}

SCENARIO("A parked poll whose deadline passes is resumed with the deadline reason", "[p15a][sync][parked-poll]")
{
    GIVEN("polls parked with different deadlines")
    {
        auto notifier = SyncNotifier{};
        auto recorder = Recorder{};
        auto destroyed = std::atomic<std::size_t>{0U};
        REQUIRE(start_registry(notifier, recorder, ParkedPollLimits{16U, 4U}));
        auto const now = std::chrono::steady_clock::now();
        auto late = make_poll("late", destroyed);
        auto soon = make_poll("soon", destroyed);
        REQUIRE(notifier.park(notifier.observe("@a:test"), now + 60s, late).has_value());
        REQUIRE(notifier.park(notifier.observe("@b:test"), now + 150ms, soon).has_value());

        WHEN("the earlier deadline passes")
        {
            REQUIRE(recorder.wait_for(1U, 5s));

            THEN("only the earlier poll is resumed, as a deadline")
            {
                auto const items = recorder.items();
                REQUIRE(items.size() == 1U);
                REQUIRE(items.front().name == "soon");
                REQUIRE(items.front().reason == WakeReason::deadline);
                REQUIRE(notifier.parking().parked() == 1U);
            }
        }
    }
}

SCENARIO("The registry refuses a park past its caps and leaves the poll with the caller", "[p15a][sync][parked-poll]")
{
    GIVEN("a registry of two polls, one per user")
    {
        auto notifier = SyncNotifier{};
        auto recorder = Recorder{};
        auto destroyed = std::atomic<std::size_t>{0U};
        REQUIRE(start_registry(notifier, recorder, ParkedPollLimits{2U, 1U}));
        auto const far = std::chrono::steady_clock::now() + 60s;
        auto first = make_poll("a1", destroyed);
        auto second = make_poll("b1", destroyed);
        REQUIRE(notifier.park(notifier.observe("@a:test"), far, first).has_value());
        REQUIRE(notifier.park(notifier.observe("@b:test"), far, second).has_value());

        WHEN("the same user parks again, and a third user parks past the total")
        {
            auto same_user = make_poll("a2", destroyed);
            auto third_user = make_poll("c1", destroyed);
            auto const same = notifier.park(notifier.observe("@a:test"), far, same_user);
            auto const total = notifier.park(notifier.observe("@c:test"), far, third_user);

            THEN("both are refused and the caller still owns both polls")
            {
                REQUIRE_FALSE(same.has_value());
                REQUIRE_FALSE(total.has_value());
                REQUIRE(same_user != nullptr);
                REQUIRE(third_user != nullptr);
                REQUIRE(notifier.parking().parked() == 2U);
            }
        }
    }
}

SCENARIO("Stopping the registry destroys every parked poll promptly and refuses later parks",
         "[p15a][sync][parked-poll]")
{
    GIVEN("a registry holding polls and a registry that was never started")
    {
        auto notifier = SyncNotifier{};
        auto idle = SyncNotifier{};
        auto recorder = Recorder{};
        auto destroyed = std::atomic<std::size_t>{0U};
        REQUIRE(start_registry(notifier, recorder, ParkedPollLimits{16U, 4U}));
        for (auto index = 0; index < 5; ++index)
        {
            auto poll = make_poll("p", destroyed);
            REQUIRE(notifier
                        .park(notifier.observe("@u" + std::to_string(index) + ":test"),
                              std::chrono::steady_clock::now() + 60s, poll)
                        .has_value());
        }

        WHEN("it is stopped")
        {
            auto const started = std::chrono::steady_clock::now();
            notifier.parking().request_stop();
            auto const elapsed = std::chrono::steady_clock::now() - started;
            auto late = make_poll("late", destroyed);
            auto const after_stop =
                notifier.park(notifier.observe("@late:test"), std::chrono::steady_clock::now() + 60s, late);
            auto never_started = make_poll("never", destroyed);
            auto const unstarted =
                idle.park(idle.observe("@a:test"), std::chrono::steady_clock::now() + 60s, never_started);

            THEN("all five polls are destroyed within a second, nothing is resumed, and later parks are refused")
            {
                REQUIRE(elapsed < 1s);
                REQUIRE(destroyed.load() == 5U);
                REQUIRE(recorder.items().empty());
                REQUIRE(notifier.parking().parked() == 0U);
                REQUIRE_FALSE(after_stop.has_value());
                REQUIRE(late != nullptr);
                REQUIRE_FALSE(unstarted.has_value());
                REQUIRE_FALSE(notifier.parking().running());
            }
        }
    }
}

SCENARIO("Many threads parking and publishing at once resume every poll exactly once", "[p15a][sync][parked-poll]")
{
    GIVEN("a registry and many parking threads released together")
    {
        constexpr auto thread_count = std::size_t{16U};
        constexpr auto per_thread = std::size_t{8U};
        auto notifier = SyncNotifier{};
        auto recorder = Recorder{};
        auto destroyed = std::atomic<std::size_t>{0U};
        REQUIRE(start_registry(notifier, recorder, ParkedPollLimits{thread_count * per_thread, per_thread}));
        auto cursors = std::vector<merovingian::sync::WaitCursor>{};
        for (auto index = std::size_t{0U}; index < thread_count; ++index)
        {
            cursors.push_back(notifier.observe("@user" + std::to_string(index) + ":test"));
        }
        auto ready = std::atomic<std::size_t>{0U};
        auto go = std::atomic<bool>{false};
        auto refused = std::atomic<std::size_t>{0U};

        WHEN("each thread parks polls for its user while another thread publishes to everyone")
        {
            {
                auto threads = merovingian::tests::JoiningThreads{};
                for (auto index = std::size_t{0U}; index < thread_count; ++index)
                {
                    threads.emplace_back([&, index] {
                        ++ready;
                        while (!go.load())
                        {
                            std::this_thread::yield();
                        }
                        for (auto count = std::size_t{0U}; count < per_thread; ++count)
                        {
                            auto poll = make_poll("t", destroyed);
                            if (!notifier.park(cursors[index], std::chrono::steady_clock::now() + 60s, poll)
                                     .has_value())
                            {
                                ++refused;
                            }
                        }
                    });
                }
                threads.emplace_back([&] {
                    ++ready;
                    while (!go.load())
                    {
                        std::this_thread::yield();
                    }
                    for (auto round = std::uint64_t{1U}; round <= 20U; ++round)
                    {
                        notifier.publish(round, round);
                        std::this_thread::yield();
                    }
                });
                while (ready.load() < thread_count + 1U)
                {
                    std::this_thread::yield();
                }
                go.store(true);
            }
            // Every cursor was taken before any publish, so every park finds a moved generation or is woken by a
            // publish: nothing may stay parked.
            auto const expected = (thread_count * per_thread) - refused.load();
            REQUIRE(recorder.wait_for(expected, 10s));

            THEN("each poll was resumed exactly once and none is left parked")
            {
                REQUIRE(refused.load() == 0U);
                REQUIRE(recorder.items().size() == thread_count * per_thread);
                REQUIRE(notifier.parking().parked() == 0U);
                REQUIRE(destroyed.load() == thread_count * per_thread);
            }
        }
    }
}
