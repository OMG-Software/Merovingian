// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |                    REQUEST LOCK RAII PRIMITIVES                         |
// |                                                                         |
// |  HomeserverRuntime::mutex is a recursive mutex held for the whole of    |
// |  every client-server request. Handlers must release it around blocking  |
// |  work, and must get it back afterwards on EVERY path — including the    |
// |  throwing one. A request that returns with the invariant broken leaves  |
// |  the next request on that thread running unsynchronised.                |
// +-------------------------------------------------------------------------+

#include "merovingian/homeserver/request_lock.hpp"

#include <catch2/catch_test_macros.hpp>

#include <mutex>
#include <stdexcept>
#include <tuple>

SCENARIO("a released guard is restored when the guarded work throws", "[homeserver][locking]")
{
    GIVEN("a recursive mutex owned by a request guard")
    {
        auto mutex = std::recursive_mutex{};
        auto guard = std::unique_lock<std::recursive_mutex>{mutex};
        REQUIRE(guard.owns_lock());

        WHEN("the guard is released for a scope that completes normally")
        {
            {
                auto const released = merovingian::homeserver::ScopedGuardRelease{guard};
                THEN("the mutex is not held for the duration of that scope")
                {
                    REQUIRE_FALSE(guard.owns_lock());
                }
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
                auto const released = merovingian::homeserver::ScopedGuardRelease{guard};
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
        auto mutex = std::recursive_mutex{};
        auto guard = std::unique_lock<std::recursive_mutex>{mutex};
        guard.unlock();
        REQUIRE_FALSE(guard.owns_lock());

        WHEN("a release scope opens and closes over it")
        {
            {
                auto const released = merovingian::homeserver::ScopedGuardRelease{guard};
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
