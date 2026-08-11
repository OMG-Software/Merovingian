// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Coverage: the reap-before-park / fixed-cap policy that bounds
// HomeserverRuntime::orphan_futures_ background task pool (used by both
// join_room's make_join race losers and room_service.cpp's
// dispatch_push_deliveries). Exercises reap_completed_futures and
// at_background_task_capacity directly, deterministically — via
// std::promise instead of real background threads — so the policy is
// provable without any timing dependence. See test_push_delivery_flow.cpp
// for the end-to-end proof that dispatch_push_deliveries actually calls
// these at the real call site.

#include "merovingian/homeserver/runtime.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstddef>
#include <future>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

SCENARIO("reap_completed_futures removes only already-finished futures", "[homeserver][runtime][push]")
{
    GIVEN("one already-completed future ahead of one still-running future")
    {
        auto done_promise = std::promise<void>{};
        auto done_future = done_promise.get_future();
        done_promise.set_value();

        auto pending_promise = std::promise<void>{};
        auto pending_future = pending_promise.get_future();

        auto futures = std::vector<std::future<void>>{};
        futures.push_back(std::move(done_future));
        futures.push_back(std::move(pending_future));

        WHEN("the vector is reaped")
        {
            merovingian::homeserver::reap_completed_futures(futures);

            THEN("only the still-running future survives, in its original relative order")
            {
                REQUIRE(futures.size() == 1U);
                REQUIRE(futures[0].valid());

                // Resolve it here so the pending promise does not go unset for the
                // rest of the test run; reap_completed_futures never touches a
                // still-running future beyond a non-blocking readiness check.
                pending_promise.set_value();
                futures[0].wait();
            }
        }
    }

    GIVEN("every future already completed")
    {
        auto futures = std::vector<std::future<void>>{};
        for (auto i = 0; i < 3; ++i)
        {
            auto promise = std::promise<void>{};
            auto future = promise.get_future();
            promise.set_value();
            futures.push_back(std::move(future));
        }

        WHEN("the vector is reaped")
        {
            merovingian::homeserver::reap_completed_futures(futures);

            THEN("the vector ends up empty rather than accumulating completed entries")
            {
                REQUIRE(futures.empty());
            }
        }
    }

    GIVEN("an empty vector")
    {
        auto futures = std::vector<std::future<void>>{};

        WHEN("the vector is reaped")
        {
            merovingian::homeserver::reap_completed_futures(futures);

            THEN("it stays empty and reaping is a no-op")
            {
                REQUIRE(futures.empty());
            }
        }
    }
}

SCENARIO("at_background_task_capacity gates new background work at a fixed bound", "[homeserver][runtime][push]")
{
    GIVEN("a cap of 3 in-flight tasks")
    {
        constexpr auto cap = std::size_t{3U};

        WHEN("fewer tasks are in flight than the cap")
        {
            THEN("there is room for one more")
            {
                REQUIRE_FALSE(merovingian::homeserver::at_background_task_capacity(0U, cap));
                REQUIRE_FALSE(merovingian::homeserver::at_background_task_capacity(2U, cap));
            }
        }

        WHEN("exactly the cap is already in flight")
        {
            THEN("the next unit of work must be dropped rather than spawned")
            {
                REQUIRE(merovingian::homeserver::at_background_task_capacity(3U, cap));
            }
        }

        WHEN("more than the cap is somehow in flight")
        {
            THEN("it still reports at capacity")
            {
                REQUIRE(merovingian::homeserver::at_background_task_capacity(4U, cap));
            }
        }
    }
}

// Regression coverage for the production-facing deadlock this branch fixes:
// dispatch_push_deliveries's background task used to decrement
// push_delivery_in_flight_ as its final action while holding
// orphan_futures_mutex_ — the same mutex HomeserverRuntime::~HomeserverRuntime()
// took for the entire drain, including its blocking future.wait() calls. A
// runtime destroyed while a push-delivery task was still in flight would
// deadlock: the destructor waited on the future while holding the mutex the
// task needed to finish, and the task could never acquire it. Fixed by (1)
// making push_delivery_in_flight_ a std::atomic so the task's decrement never
// needs the mutex at all, and (2) having the destructor hold the mutex only
// long enough to move the futures out of orphan_futures_, releasing it before
// the blocking wait(). This test exercises (2) directly and deterministically:
// the parked task is held closed on an external gate for the whole polling
// window, so the destructor cannot finish regardless of its locking
// discipline — a destructor that still holds the mutex across the wait will
// show it held for the entire window (nothing else can free it); a destructor
// that releases it first will show it free almost immediately.
SCENARIO("HomeserverRuntime's destructor releases orphan_futures_mutex_ before blocking on a still-running "
         "background task",
         "[homeserver][runtime][push]")
{
    GIVEN("a runtime with a push-delivery-shaped background task parked in orphan_futures_, still blocked on "
          "external I/O when destruction begins")
    {
        auto runtime_holder = std::make_unique<merovingian::homeserver::HomeserverRuntime>();
        auto& mutex_ref = runtime_holder->orphan_futures_mutex_;

        auto release_promise = std::promise<void>{};
        auto release_future = release_promise.get_future();

        // Mirrors dispatch_push_deliveries's real background task: its only
        // remaining work is gated on external I/O (here, a promise standing
        // in for a slow push gateway) and, matching the fix, its completion
        // never needs orphan_futures_mutex_.
        auto task_future = std::async(std::launch::async, [fut = std::move(release_future)]() mutable {
            fut.wait();
        });

        {
            auto const lock = std::lock_guard{mutex_ref};
            runtime_holder->orphan_futures_.push_back(std::move(task_future));
        }

        WHEN("the runtime is destroyed on another thread while the background task is still blocked")
        {
            auto destruct_thread = std::thread{[holder = std::move(runtime_holder)]() mutable {
                holder.reset();
            }};

            // The task's gate stays closed for this entire window, so the
            // destructor's future.wait() cannot return no matter what it
            // does with the mutex — this makes the poll below unambiguous.
            auto acquired_promptly = false;
            auto const deadline = std::chrono::steady_clock::now() + std::chrono::seconds{2};
            while (std::chrono::steady_clock::now() < deadline)
            {
                if (mutex_ref.try_lock())
                {
                    mutex_ref.unlock();
                    acquired_promptly = true;
                    break;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds{1});
            }

            // Open the gate so the task — and, transitively, the
            // destructor's wait() — can finish regardless of the outcome
            // above, then join before asserting: a still-joinable
            // std::thread destroyed while unwinding a failed REQUIRE calls
            // std::terminate instead of reporting the failure.
            release_promise.set_value();
            destruct_thread.join();

            THEN("the mutex became available again while the background task was still running")
            {
                REQUIRE(acquired_promptly);
            }
        }
    }
}
