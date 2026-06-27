// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/worker_supervisor.hpp"

#include <catch2/catch_test_macros.hpp>

namespace
{

using merovingian::homeserver::WorkerSupervisor;

} // namespace

SCENARIO("WorkerSupervisor construction captures shard index and timeout", "[federation][worker-supervisor]")
{
    GIVEN("a supervisor configured for shard 7")
    {
        WHEN("it is constructed without starting")
        {
            auto supervisor = WorkerSupervisor{"/nonexistent/worker", "/nonexistent/config", 30U, 7U};

            THEN("the shard index and timeout are preserved")
            {
                REQUIRE(supervisor.shard_index() == 7U);
                REQUIRE(supervisor.request_timeout() == 30U);
            }
        }
    }
}

SCENARIO("WorkerSupervisor defaults to shard 0 when omitted", "[federation][worker-supervisor]")
{
    GIVEN("a supervisor constructed without a shard argument")
    {
        WHEN("it is constructed")
        {
            auto supervisor = WorkerSupervisor{"/nonexistent/worker", "/nonexistent/config", 30U};

            THEN("shard index defaults to 0")
            {
                REQUIRE(supervisor.shard_index() == 0U);
            }
        }
    }
}

SCENARIO("WorkerSupervisor reports healthy before start", "[federation][worker-supervisor]")
{
    GIVEN("a freshly constructed supervisor")
    {
        WHEN("its health is queried before start()")
        {
            auto supervisor = WorkerSupervisor{"/nonexistent/worker", "/nonexistent/config", 30U, 2U};

            THEN("it reports healthy")
            {
                REQUIRE(supervisor.healthy());
            }
        }
    }
}

SCENARIO("WorkerSupervisor stop is idempotent before start", "[federation][worker-supervisor][lifecycle]")
{
    GIVEN("a freshly constructed supervisor")
    {
        WHEN("stop is called before start and again after")
        {
            auto supervisor = WorkerSupervisor{"/nonexistent/worker", "/nonexistent/config", 30U, 2U};
            supervisor.stop();
            supervisor.stop();

            THEN("the supervisor remains healthy and does not crash")
            {
                REQUIRE(supervisor.healthy());
            }
        }
    }
}

SCENARIO("WorkerSupervisor exposes timeout and shard getters", "[federation][worker-supervisor]")
{
    GIVEN("a supervisor configured with a 45-second timeout and shard 9")
    {
        WHEN("the getters are queried")
        {
            auto supervisor = WorkerSupervisor{"/nonexistent/worker", "/nonexistent/config", 45U, 9U};

            THEN("the original values are returned")
            {
                REQUIRE(supervisor.request_timeout() == 45U);
                REQUIRE(supervisor.shard_index() == 9U);
            }
        }
    }
}
