// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// PeriodicJob: the dedicated thread that drains background delivery queues
// (appservice transactions, deferred federation PDUs). Assertions run on the
// test thread only; the job body touches nothing but atomics.

#include "merovingian/homeserver/periodic_job.hpp"
#include "merovingian/homeserver/stop_flag.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <stdexcept>
#include <thread>

using namespace std::chrono_literals;

namespace
{

// Polls `predicate` for up to `limit`; true as soon as it holds.
template <typename Predicate>
[[nodiscard]] auto eventually(Predicate predicate, std::chrono::milliseconds limit) -> bool
{
    auto const deadline = std::chrono::steady_clock::now() + limit;
    while (std::chrono::steady_clock::now() < deadline)
    {
        if (predicate())
        {
            return true;
        }
        std::this_thread::sleep_for(5ms);
    }
    return predicate();
}

} // namespace

SCENARIO("A periodic job runs once at start and again whenever it is woken", "[homeserver][periodic_job]")
{
    GIVEN("a started job that asks never to be re-run on a timer")
    {
        auto runs = std::atomic<int>{0};
        auto job = merovingian::homeserver::PeriodicJob{"test", [&runs](merovingian::homeserver::StopFlag const&) {
                                                            runs.fetch_add(1);
                                                            return std::chrono::milliseconds{1h};
                                                        }};
        REQUIRE(job.start());
        REQUIRE(eventually(
            [&runs]() {
                return runs.load() >= 1;
            },
            2s));

        WHEN("it is woken")
        {
            auto const before = runs.load();
            job.wake();

            THEN("it runs again without waiting for its timer")
            {
                CHECK(eventually(
                    [&runs, before]() {
                        return runs.load() > before;
                    },
                    2s));
            }
        }
    }
}

SCENARIO("A periodic job re-runs after the delay its last run asked for", "[homeserver][periodic_job]")
{
    GIVEN("a started job that asks to be re-run after 10 ms")
    {
        auto runs = std::atomic<int>{0};
        auto job = merovingian::homeserver::PeriodicJob{"test", [&runs](merovingian::homeserver::StopFlag const&) {
                                                            runs.fetch_add(1);
                                                            return std::chrono::milliseconds{10};
                                                        }};
        REQUIRE(job.start());

        WHEN("nobody wakes it")
        {
            THEN("it still runs repeatedly")
            {
                CHECK(eventually(
                    [&runs]() {
                        return runs.load() >= 3;
                    },
                    5s));
            }
        }
    }
}

SCENARIO("A stopped periodic job runs no more", "[homeserver][periodic_job]")
{
    GIVEN("a started job")
    {
        auto runs = std::atomic<int>{0};
        auto job = merovingian::homeserver::PeriodicJob{"test", [&runs](merovingian::homeserver::StopFlag const&) {
                                                            runs.fetch_add(1);
                                                            return std::chrono::milliseconds{1};
                                                        }};
        REQUIRE(job.start());
        REQUIRE(eventually(
            [&runs]() {
                return runs.load() >= 1;
            },
            2s));

        WHEN("it is stopped")
        {
            job.stop();
            auto const after_stop = runs.load();
            job.wake();
            std::this_thread::sleep_for(50ms);

            THEN("its thread has ended and the job never runs again")
            {
                CHECK_FALSE(job.running());
                CHECK(runs.load() == after_stop);
            }
        }
    }
}

SCENARIO("A periodic job survives a run that throws", "[homeserver][periodic_job]")
{
    GIVEN("a job whose first run throws")
    {
        auto runs = std::atomic<int>{0};
        auto job = merovingian::homeserver::PeriodicJob{
            "test", [&runs](merovingian::homeserver::StopFlag const&) -> std::chrono::milliseconds {
                if (runs.fetch_add(1) == 0)
                {
                    throw std::runtime_error{"first run fails"};
                }
                return std::chrono::milliseconds{1h};
            }};

        WHEN("it is started and woken after the failure")
        {
            REQUIRE(job.start());
            REQUIRE(eventually(
                [&runs]() {
                    return runs.load() >= 1;
                },
                2s));
            job.wake();

            THEN("the thread is still alive and runs the job again")
            {
                CHECK(eventually(
                    [&runs]() {
                        return runs.load() >= 2;
                    },
                    2s));
                CHECK(job.running());
            }
        }
    }
}

SCENARIO("A periodic job that was never started is inert", "[homeserver][periodic_job]")
{
    GIVEN("a job that is constructed but not started")
    {
        auto runs = std::atomic<int>{0};
        auto job = merovingian::homeserver::PeriodicJob{"test", [&runs](merovingian::homeserver::StopFlag const&) {
                                                            runs.fetch_add(1);
                                                            return std::chrono::milliseconds{1};
                                                        }};

        WHEN("it is woken and stopped")
        {
            job.wake();
            job.stop();

            THEN("the job never ran and nothing is running")
            {
                CHECK(runs.load() == 0);
                CHECK_FALSE(job.running());
            }
        }
    }
}

SCENARIO("Stopping a periodic job ends a run that is polling its stop flag", "[homeserver][periodic_job]")
{
    GIVEN("a started job whose run loops until it sees a stop request")
    {
        auto entered = std::atomic<bool>{false};
        auto saw_stop = std::atomic<bool>{false};
        auto job = merovingian::homeserver::PeriodicJob{
            "test", [&entered, &saw_stop](merovingian::homeserver::StopFlag const& stop) {
                entered.store(true);
                while (!stop.stop_requested())
                {
                    std::this_thread::sleep_for(1ms);
                }
                saw_stop.store(true);
                return std::chrono::milliseconds{1h};
            }};
        REQUIRE(job.start());
        REQUIRE(eventually(
            [&entered]() {
                return entered.load();
            },
            2s));

        WHEN("it is stopped mid-run")
        {
            job.stop();

            THEN("the run saw the stop request and the thread has ended")
            {
                CHECK(saw_stop.load());
                CHECK_FALSE(job.running());
            }
        }
    }
}
