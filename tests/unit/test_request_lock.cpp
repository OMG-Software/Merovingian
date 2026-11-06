// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |                    REQUEST LOCK RAII PRIMITIVES                         |
// |                                                                         |
// |  HomeserverRuntime::mutex is a RECURSIVE mutex held for the whole of    |
// |  every client-server request. Handlers must release it around blocking  |
// |  work, and must get it back afterwards on EVERY path — including the    |
// |  throwing one. A request that returns with the invariant broken leaves  |
// |  the next request on that thread running unsynchronised.                |
// |                                                                         |
// |  Recursion is what makes this hard: a self-locking service function     |
// |  called from a request handler holds the mutex TWICE. Releasing one     |
// |  level leaves the mutex locked across the network call, and every other |
// |  client request and inbound federation transaction stalls behind it —   |
// |  shipped as a defect in 0.12.1, 0.12.3 and 0.12.6. The scenarios below  |
// |  assert on what another thread can observe, not on what a guard         |
// |  believes, because only the former distinguishes those cases.           |
// +-------------------------------------------------------------------------+

#include "merovingian/homeserver/request_lock.hpp"
#include "merovingian/homeserver/runtime_mutex.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <cstddef>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <tuple>

namespace
{

using merovingian::homeserver::RequestLockScope;
using merovingian::homeserver::RuntimeLock;
using merovingian::homeserver::RuntimeLockRelease;
using merovingian::homeserver::RuntimeMutex;

// Answers "is this mutex free right now?" from a thread that holds no level of
// it. A recursive mutex answers try_lock() with "yes" for its own owner
// whatever the depth, so the question can only be asked from elsewhere.
//
// Catch2's assertion macros are not thread-safe, so the probe thread only sets
// an atomic and the caller asserts on the main thread.
[[nodiscard]] auto free_to_another_thread(RuntimeMutex& mutex) -> bool
{
    auto acquired = std::atomic<bool>{false};
    auto probe = std::thread{[&mutex, &acquired] {
        if (mutex.try_lock())
        {
            acquired.store(true);
            mutex.unlock();
        }
    }};
    probe.join();
    return acquired.load();
}

} // namespace

SCENARIO("a released guard is restored when the guarded work throws", "[homeserver][locking]")
{
    GIVEN("a runtime mutex owned by a request guard")
    {
        auto mutex = RuntimeMutex{};
        auto guard = RuntimeLock{mutex};
        REQUIRE(guard.owns_lock());

        WHEN("the guard is released for a scope that completes normally")
        {
            auto free_during_scope = false;
            {
                auto const released = RuntimeLockRelease{guard};
                std::ignore = released;
                free_during_scope = free_to_another_thread(mutex);
            }

            THEN("the mutex was genuinely free for the duration of that scope")
            {
                REQUIRE(free_during_scope);
            }

            THEN("the guard owns the mutex again afterwards")
            {
                REQUIRE(guard.owns_lock());
            }
        }

        WHEN("the guarded work throws")
        {
            auto threw = false;
            try
            {
                auto const released = RuntimeLockRelease{guard};
                std::ignore = released;
                throw std::runtime_error{"outbound call failed"};
            }
            catch (std::runtime_error const&)
            {
                threw = true;
            }

            THEN("the exception still propagates")
            {
                REQUIRE(threw);
            }

            THEN("the guard owns the mutex again")
            {
                // The bare `guard.unlock(); f(); guard.lock();` triple this
                // replaces would leave the mutex released here, because
                // unique_lock's destructor does not re-acquire a lock it no
                // longer owns.
                REQUIRE(guard.owns_lock());
            }
        }
    }
}

SCENARIO("releasing a guard that does not own the mutex is a no-op", "[homeserver][locking]")
{
    GIVEN("a guard that has already been released by hand")
    {
        auto mutex = RuntimeMutex{};
        auto guard = RuntimeLock{mutex};
        guard.unlock();
        REQUIRE_FALSE(guard.owns_lock());

        WHEN("a release scope opens and closes over it")
        {
            {
                auto const released = RuntimeLockRelease{guard};
                std::ignore = released;
            }

            THEN("the guard is left as it was found, not acquired")
            {
                // Re-acquiring here would hand the caller a lock it never held,
                // and the caller would go on to release it once — dropping the
                // recursion depth of a mutex someone else still relies on.
                REQUIRE_FALSE(guard.owns_lock());
            }
        }
    }
}

SCENARIO("a release scope frees the mutex even when an outer frame also holds it", "[homeserver][locking][security]")
{
    // This is the shape of every deadlock this primitive exists to prevent: a
    // dispatcher holds runtime.mutex for the whole request, then calls a
    // service function that locks it again for its own validation and releases
    // "the lock" before its outbound call.
    GIVEN("a dispatcher guard and a nested service guard on the same runtime mutex")
    {
        auto mutex = RuntimeMutex{};
        auto dispatcher_guard = RuntimeLock{mutex};
        auto service_guard = RuntimeLock{mutex};
        REQUIRE(dispatcher_guard.owns_lock());
        REQUIRE(service_guard.owns_lock());
        REQUIRE_FALSE(free_to_another_thread(mutex));

        WHEN("the service releases the guard it holds for a blocking call")
        {
            auto free_during_scope = false;
            auto released_levels = std::size_t{0U};
            {
                auto const released = RuntimeLockRelease{service_guard};
                free_during_scope = free_to_another_thread(mutex);
                released_levels = released.levels_released();
            }

            THEN("no level of the mutex is left held across that call")
            {
                // Releasing only the service's own guard would leave the
                // dispatcher's level held and this would be false — the
                // server serialised behind one slow peer.
                REQUIRE(free_during_scope);
            }

            THEN("both levels are reported as released")
            {
                REQUIRE(released_levels == 2U);
            }

            THEN("both frames own the mutex again afterwards")
            {
                REQUIRE(service_guard.owns_lock());
                REQUIRE(dispatcher_guard.owns_lock());
                REQUIRE(mutex.held_by_current_thread());
                REQUIRE_FALSE(free_to_another_thread(mutex));
            }
        }

        WHEN("the guarded work throws while an outer frame also holds the mutex")
        {
            auto threw = false;
            try
            {
                auto const released = RuntimeLockRelease{service_guard};
                std::ignore = released;
                throw std::runtime_error{"outbound call failed"};
            }
            catch (std::runtime_error const&)
            {
                threw = true;
            }

            THEN("the exception propagates and every level is restored")
            {
                REQUIRE(threw);
                REQUIRE(service_guard.owns_lock());
                REQUIRE(dispatcher_guard.owns_lock());
                REQUIRE_FALSE(free_to_another_thread(mutex));
            }
        }
    }
}

SCENARIO("the published-guard release frees the mutex whichever guard was published", "[homeserver][locking][security]")
{
    // NetworkIoUnlock and ScopedGuardRelease used to differ here: one acted on
    // the thread's published guard, the other on a guard in hand, and picking
    // the wrong one compiled, passed tests, and held the mutex across a
    // network round trip. Both constructors now free the mutex outright.
    GIVEN("a published dispatcher guard and an unpublished nested guard")
    {
        auto mutex = RuntimeMutex{};
        auto dispatcher_guard = RuntimeLock{mutex};
        auto const published = RequestLockScope{dispatcher_guard};
        std::ignore = published;
        auto service_guard = RuntimeLock{mutex};
        REQUIRE_FALSE(free_to_another_thread(mutex));

        WHEN("a release scope opens on the published guard rather than the nested one")
        {
            auto free_during_scope = false;
            {
                auto const released = RuntimeLockRelease{};
                std::ignore = released;
                free_during_scope = free_to_another_thread(mutex);
            }

            THEN("the nested level is released too")
            {
                REQUIRE(free_during_scope);
            }

            THEN("both guards own the mutex again afterwards")
            {
                REQUIRE(dispatcher_guard.owns_lock());
                REQUIRE(service_guard.owns_lock());
                REQUIRE_FALSE(free_to_another_thread(mutex));
            }
        }
    }

    GIVEN("no published guard and no guard in hand")
    {
        WHEN("a release scope opens and closes")
        {
            auto const opened = [] {
                auto const released = RuntimeLockRelease{};
                return released.levels_released();
            }();

            THEN("it does nothing at all")
            {
                // The federation worker and direct-call tests reach service
                // functions without a request guard on the stack.
                REQUIRE(opened == 0U);
            }
        }
    }
}

SCENARIO("release scopes nest without corrupting the recursion depth", "[homeserver][locking][security]")
{
    // A release scope drops recursion levels through the mutex itself, because
    // it has no way to reach the `unique_lock` objects that own them. Those
    // guards therefore keep reporting `owns_lock() == true` while the mutex is
    // free, and an inner scope that trusted that flag would unlock a mutex the
    // thread no longer holds: the recursion depth underflows and the runtime
    // mutex is left permanently locked. Nothing outside the primitive reads
    // `owns_lock()`, so the scope reads the mutex instead.
    GIVEN("a published dispatcher guard and a nested service guard")
    {
        auto mutex = RuntimeMutex{};
        auto dispatcher_guard = RuntimeLock{mutex};
        auto const published = RequestLockScope{dispatcher_guard};
        std::ignore = published;
        auto service_guard = RuntimeLock{mutex};
        REQUIRE_FALSE(free_to_another_thread(mutex));

        WHEN("a second release scope opens inside the first")
        {
            auto free_in_outer = false;
            auto free_in_inner = false;
            auto inner_levels = std::size_t{1U};
            {
                auto const outer = RuntimeLockRelease{service_guard};
                std::ignore = outer;
                free_in_outer = free_to_another_thread(mutex);
                {
                    // A helper deeper in the call stack reaching for the
                    // thread's published guard, which the outer scope has
                    // already drained.
                    auto const inner = RuntimeLockRelease{};
                    free_in_inner = free_to_another_thread(mutex);
                    inner_levels = inner.levels_released();
                }
                THEN("the inner scope finds nothing left to release")
                {
                    REQUIRE(inner_levels == 0U);
                }
            }

            THEN("the mutex is free throughout both scopes")
            {
                REQUIRE(free_in_outer);
                REQUIRE(free_in_inner);
            }

            THEN("every level is restored exactly once when both scopes close")
            {
                REQUIRE(mutex.held_by_current_thread());
                REQUIRE_FALSE(free_to_another_thread(mutex));
                // Two acquisitions were taken and two must remain. Releasing
                // both frees the mutex; a depth that underflowed or was
                // restored twice leaves it held here, and unlocking a mutex
                // this thread does not own is undefined behaviour TSan reports.
                service_guard.unlock();
                REQUIRE(mutex.held_by_current_thread());
                dispatcher_guard.unlock();
                REQUIRE_FALSE(mutex.held_by_current_thread());
                REQUIRE(free_to_another_thread(mutex));
            }
        }

        WHEN("code inside a release scope takes a fresh lock and releases again")
        {
            auto free_before_fresh_lock = false;
            auto held_with_fresh_lock = false;
            auto free_in_inner = false;
            auto inner_levels = std::size_t{0U};
            {
                auto const outer = RuntimeLockRelease{service_guard};
                std::ignore = outer;
                free_before_fresh_lock = free_to_another_thread(mutex);

                auto fresh_guard = RuntimeLock{mutex};
                held_with_fresh_lock = !free_to_another_thread(mutex);
                {
                    auto const inner = RuntimeLockRelease{fresh_guard};
                    free_in_inner = free_to_another_thread(mutex);
                    inner_levels = inner.levels_released();
                }
                REQUIRE(mutex.held_by_current_thread());
            }

            THEN("the fresh level is released for the inner scope and restored after it")
            {
                REQUIRE(free_before_fresh_lock);
                REQUIRE(held_with_fresh_lock);
                REQUIRE(free_in_inner);
                REQUIRE(inner_levels == 1U);
            }

            THEN("both original levels are restored when the outer scope closes")
            {
                REQUIRE(mutex.held_by_current_thread());
                service_guard.unlock();
                REQUIRE(mutex.held_by_current_thread());
                dispatcher_guard.unlock();
                REQUIRE_FALSE(mutex.held_by_current_thread());
            }
        }
    }
}

SCENARIO("the runtime mutex reports ownership by the calling thread", "[homeserver][locking]")
{
    GIVEN("an unheld runtime mutex")
    {
        auto mutex = RuntimeMutex{};

        THEN("no thread owns it")
        {
            REQUIRE_FALSE(mutex.held_by_current_thread());
            REQUIRE(free_to_another_thread(mutex));
        }

        WHEN("the calling thread locks it twice")
        {
            mutex.lock();
            mutex.lock();

            THEN("it reports ownership by this thread and not by any other")
            {
                REQUIRE(mutex.held_by_current_thread());
                REQUIRE_FALSE(free_to_another_thread(mutex));
                mutex.unlock();
                mutex.unlock();
            }

            THEN("ownership survives releasing one level and ends with the last")
            {
                mutex.unlock();
                REQUIRE(mutex.held_by_current_thread());
                mutex.unlock();
                REQUIRE_FALSE(mutex.held_by_current_thread());
                REQUIRE(free_to_another_thread(mutex));
            }
        }
    }
}
