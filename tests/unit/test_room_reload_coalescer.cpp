// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
// Release-gate audit, resource-exhaustion.federation-worker-room-sync.uncoalesced-full-room-reload-per-accepted-pdu
// (ADR-0623). One accepted PDU is one `room_sync`, and a reload re-reads the whole room. These scenarios drive
// RoomReloadCoalescer with a model of main's commit-then-notify and of the worker's reload thread: what they assert is
// the number of reloads and what the last one read. Interleavings are forced by the test, never by waiting.

#include "merovingian/federation_worker/RoomReloadCoalescer.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <semaphore>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace
{

using merovingian::federation_worker::RoomReloadCoalescer;

// Main's commit, its notification, and a single-threaded reload queue. `committed` is the database.
struct Model final
{
    RoomReloadCoalescer coalescer{};
    std::uint64_t committed{0U};
    std::uint64_t snapshot{0U};
    std::uint64_t reported_generation{0U};
    std::size_t reloads{0U};
    std::deque<std::string> scheduled{};
    // Runs between the reload's database read and the end of the round: a PDU the read missed.
    std::function<void()> after_read{};

    auto commit_and_notify(std::string const& room) -> void
    {
        ++committed;
        if (coalescer.note_changed(room, committed))
        {
            scheduled.push_back(room);
        }
    }

    auto run_next() -> void
    {
        auto const room = scheduled.front();
        scheduled.pop_front();
        auto const again = coalescer.run_round(room, [this](std::uint64_t generation) {
            ++reloads;
            snapshot = committed;
            reported_generation = generation;
            if (after_read)
            {
                std::invoke(std::exchange(after_read, {}));
            }
        });
        if (again)
        {
            scheduled.push_back(room);
        }
    }

    auto drain() -> void
    {
        while (!scheduled.empty())
        {
            run_next();
        }
    }
};

} // namespace

SCENARIO("A burst of room_sync notifications for one room costs one reload",
         "[federation_worker][room-reload-coalesce][security]")
{
    GIVEN("a room with no reload scheduled")
    {
        auto model = Model{};

        WHEN("a thousand PDUs are committed and notified before the reload thread runs")
        {
            for (auto pdu = 0; pdu < 1000; ++pdu)
            {
                model.commit_and_notify("!a:example.org");
            }
            model.drain();

            THEN("exactly one reload runs, it reads the last PDU, and it reports the newest generation")
            {
                REQUIRE(model.reloads == 1U);
                REQUIRE(model.snapshot == 1000U);
                REQUIRE(model.reported_generation == 1000U);
                REQUIRE(model.coalescer.scheduled_rooms() == 0U);
            }
        }

        WHEN("one PDU is committed and reloaded, and later another")
        {
            model.commit_and_notify("!a:example.org");
            model.drain();
            model.commit_and_notify("!a:example.org");
            model.drain();

            THEN("each gets its own reload, because a finished room is scheduled afresh")
            {
                REQUIRE(model.reloads == 2U);
                REQUIRE(model.snapshot == 2U);
            }
        }
    }
}

SCENARIO("The last PDU of a burst is always followed by a reload that sees it",
         "[federation_worker][room-reload-coalesce][security]")
{
    GIVEN("a reload whose database read has just finished")
    {
        auto model = Model{};
        model.commit_and_notify("!a:example.org");

        WHEN("a PDU the read missed is committed and notified before the round ends")
        {
            model.after_read = [&model] {
                model.commit_and_notify("!a:example.org");
            };
            model.drain();

            THEN("exactly one more reload runs and it reads that PDU")
            {
                REQUIRE(model.reloads == 2U);
                REQUIRE(model.snapshot == 2U);
                REQUIRE(model.reported_generation == 2U);
            }
        }

        WHEN("a hundred PDUs the read missed arrive before the round ends")
        {
            model.after_read = [&model] {
                for (auto pdu = 0; pdu < 100; ++pdu)
                {
                    model.commit_and_notify("!a:example.org");
                }
            };
            model.drain();

            THEN("still exactly one more reload runs, and it reads the last")
            {
                REQUIRE(model.reloads == 2U);
                REQUIRE(model.snapshot == 101U);
                REQUIRE(model.coalescer.scheduled_rooms() == 0U);
            }
        }
    }

    GIVEN("two rooms")
    {
        auto model = Model{};

        WHEN("both change")
        {
            model.commit_and_notify("!a:example.org");
            model.commit_and_notify("!b:example.org");
            model.commit_and_notify("!a:example.org");

            THEN("each is scheduled once, so one room's burst does not cover the other")
            {
                REQUIRE(model.scheduled.size() == 2U);
                REQUIRE(model.coalescer.scheduled_rooms() == 2U);
            }
        }
    }
}

SCENARIO("A round that throws, or that cannot be scheduled, does not leave the room stuck",
         "[federation_worker][room-reload-coalesce]")
{
    GIVEN("a scheduled room")
    {
        auto coalescer = RoomReloadCoalescer{};
        REQUIRE(coalescer.note_changed("!a:example.org", 1U));

        WHEN("the reload throws")
        {
            auto const again = coalescer.run_round("!a:example.org", [](std::uint64_t) {
                throw std::runtime_error{"database gone"};
            });

            THEN("the round ends, and the next notification schedules the room again")
            {
                REQUIRE_FALSE(again);
                REQUIRE(coalescer.note_changed("!a:example.org", 2U));
            }
        }

        WHEN("the scheduler refuses it and the room is abandoned")
        {
            coalescer.abandon("!a:example.org");

            THEN("no room is left scheduled")
            {
                REQUIRE(coalescer.scheduled_rooms() == 0U);
                REQUIRE(coalescer.note_changed("!a:example.org", 2U));
            }
        }
    }
}

SCENARIO("A notification that arrives while another thread is reloading is not lost",
         "[federation_worker][room-reload-coalesce][concurrency][security]")
{
    GIVEN("a reload held inside its database read on another thread")
    {
        auto coalescer = RoomReloadCoalescer{};
        REQUIRE(coalescer.note_changed("!a:example.org", 1U));
        auto entered = std::binary_semaphore{0};
        auto release = std::binary_semaphore{0};
        auto again = false;
        auto reader = std::thread{[&] {
            again = coalescer.run_round("!a:example.org", [&](std::uint64_t) {
                entered.release();
                release.acquire();
            });
        }};
        entered.acquire();

        WHEN("a notification is recorded during that read")
        {
            auto const must_schedule = coalescer.note_changed("!a:example.org", 2U);
            release.release();
            reader.join();

            THEN("it schedules nothing itself, and the round in progress asks for another")
            {
                REQUIRE_FALSE(must_schedule);
                REQUIRE(again);
                REQUIRE(coalescer.scheduled_rooms() == 1U);
            }
        }
    }

    GIVEN("eight threads notifying at once while one thread runs every round")
    {
        constexpr auto notifiers = 8U;
        constexpr auto each = std::uint64_t{500U};
        auto coalescer = RoomReloadCoalescer{};
        auto next_generation = std::atomic<std::uint64_t>{0U};
        auto schedule_mutex = std::mutex{};
        auto scheduled = std::deque<std::string>{};
        auto stop = std::atomic<bool>{false};
        auto last_read = std::uint64_t{0U};
        auto start = std::atomic<bool>{false};

        WHEN("every notification has been recorded and the reload thread has drained the room")
        {
            auto reloader = std::thread{[&] {
                while (true)
                {
                    auto room = std::string{};
                    {
                        auto const lock = std::lock_guard{schedule_mutex};
                        if (scheduled.empty())
                        {
                            if (stop.load())
                            {
                                return;
                            }
                            continue;
                        }
                        room = scheduled.front();
                        scheduled.pop_front();
                    }
                    auto const again = coalescer.run_round(room, [&](std::uint64_t) {
                        last_read = next_generation.load();
                    });
                    if (again)
                    {
                        auto const lock = std::lock_guard{schedule_mutex};
                        scheduled.push_back(room);
                    }
                }
            }};
            auto threads = std::vector<std::thread>{};
            for (auto index = 0U; index < notifiers; ++index)
            {
                threads.emplace_back([&] {
                    while (!start.load())
                    {
                    }
                    for (auto pdu = std::uint64_t{0U}; pdu < each; ++pdu)
                    {
                        auto const generation = ++next_generation;
                        if (coalescer.note_changed("!a:example.org", generation))
                        {
                            auto const lock = std::lock_guard{schedule_mutex};
                            scheduled.emplace_back("!a:example.org");
                        }
                    }
                });
            }
            start.store(true);
            for (auto& thread : threads)
            {
                thread.join();
            }
            // Every note_changed has returned and any round it needs is queued; stop only after the queue is empty
            // and the room is no longer scheduled.
            while (coalescer.scheduled_rooms() != 0U)
            {
                std::this_thread::yield();
            }
            stop.store(true);
            reloader.join();

            THEN("the last read saw the last commit")
            {
                REQUIRE(last_read == notifiers * each);
            }
        }
    }
}
