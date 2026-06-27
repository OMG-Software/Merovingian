// SPDX-License-Identifier: GPL-3.0-or-later

#include "../../src/federation_worker/worker_event_loop.hpp"

#include <catch2/catch_test_macros.hpp>

namespace
{

using merovingian::core::FileDescriptor;
using merovingian::federation_worker::WorkerEventLoop;

} // namespace

SCENARIO("WorkerEventLoop construction captures shard index", "[federation-worker][event-loop]")
{
    GIVEN("a worker event loop configured for shard 5")
    {
        WHEN("it is constructed with an invalid IPC fd")
        {
            auto loop = WorkerEventLoop{FileDescriptor{FileDescriptor::invalid}, merovingian::config::Config{}, 1U, 5U};

            THEN("the shard index is preserved")
            {
                REQUIRE(loop.shard_index() == 5U);
            }
        }
    }
}

SCENARIO("WorkerEventLoop defaults to shard 0 when omitted", "[federation-worker][event-loop]")
{
    GIVEN("a worker event loop constructed without a shard argument")
    {
        WHEN("it is constructed")
        {
            auto loop = WorkerEventLoop{FileDescriptor{FileDescriptor::invalid}, merovingian::config::Config{}, 1U};

            THEN("shard index defaults to 0")
            {
                REQUIRE(loop.shard_index() == 0U);
            }
        }
    }
}

SCENARIO("WorkerEventLoop run exits when the IPC fd is invalid", "[federation-worker][event-loop][lifecycle]")
{
    GIVEN("a worker event loop with an invalid IPC fd")
    {
        auto loop = WorkerEventLoop{FileDescriptor{FileDescriptor::invalid}, merovingian::config::Config{}, 1U, 3U};

        WHEN("run is invoked on a separate thread")
        {
            THEN("the constructor-time key exchange fails and run propagates the exception")
            {
                REQUIRE_THROWS_AS(loop.run(), std::runtime_error);
            }
        }
    }
}
