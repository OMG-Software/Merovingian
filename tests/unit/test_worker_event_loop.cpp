// SPDX-License-Identifier: GPL-3.0-or-later

#include "../../src/federation_worker/worker_event_loop.hpp"
#include "merovingian/crypto/ipc_auth_key.hpp"
#include "merovingian/net/thread_pool.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <thread>
#include <vector>

#include <unistd.h>

namespace
{

using merovingian::core::FileDescriptor;
using merovingian::federation_worker::WorkerEventLoop;
using merovingian::net::ThreadPool;

// Builds a real pipe carrying exactly one well-formed IPC auth key and
// returns its read end, the same shape WorkerSupervisor::spawn_and_connect
// hands the real worker over its inherited key-fd. Used so run() gets past
// federation_worker::read_ipc_auth_key and reaches the IpcChannel
// constructor, which is what the scenarios below actually exercise.
[[nodiscard]] auto make_valid_key_fd() -> FileDescriptor
{
    auto fds = std::array<int, 2>{-1, -1};
    REQUIRE(::pipe(fds.data()) == 0);
    auto write_fd = FileDescriptor{fds[1]};
    auto read_fd = FileDescriptor{fds[0]};

    auto const key_bytes = std::vector<std::uint8_t>(merovingian::crypto::kIpcAuthKeyBytes, std::uint8_t{0x42U});
    auto written = std::size_t{0U};
    while (written < key_bytes.size())
    {
        auto const rc = ::write(write_fd.get(), key_bytes.data() + written, key_bytes.size() - written);
        REQUIRE(rc > 0);
        written += static_cast<std::size_t>(rc);
    }
    write_fd.reset(); // close so the reader observes EOF right after the key

    return read_fd;
}

} // namespace

SCENARIO("WorkerEventLoop construction captures shard index", "[federation-worker][event-loop]")
{
    GIVEN("a worker event loop configured for shard 5")
    {
        WHEN("it is constructed with invalid IPC fds")
        {
            auto loop = WorkerEventLoop{FileDescriptor{FileDescriptor::invalid},
                                        FileDescriptor{FileDescriptor::invalid}, merovingian::config::Config{}, 1U, 5U};

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
            auto loop = WorkerEventLoop{FileDescriptor{FileDescriptor::invalid},
                                        FileDescriptor{FileDescriptor::invalid}, merovingian::config::Config{}, 1U};

            THEN("shard index defaults to 0")
            {
                REQUIRE(loop.shard_index() == 0U);
            }
        }
    }
}

SCENARIO("WorkerEventLoop run exits when the IPC fd is invalid", "[federation-worker][event-loop][lifecycle]")
{
    GIVEN("a worker event loop with a valid key-fd but an invalid IPC fd")
    {
        // A valid key-fd is required to reach the IpcChannel constructor this
        // scenario actually exercises: run() reads the IPC auth key first
        // (federation_worker::read_ipc_auth_key) and, since the worker no
        // longer opens the master-key file itself (ADR-0062), a missing or
        // unreadable key-fd would make run() fail closed and return before
        // ever reaching the key exchange, not throw.
        auto loop = WorkerEventLoop{FileDescriptor{FileDescriptor::invalid}, make_valid_key_fd(),
                                    merovingian::config::Config{}, 1U, 3U};

        WHEN("run is invoked on a separate thread")
        {
            THEN("the constructor-time key exchange fails and run propagates the exception")
            {
                REQUIRE_THROWS_AS(loop.run(), std::runtime_error);
            }
        }
    }
}

SCENARIO("ThreadPool submission failure is visible to WorkerEventLoop dispatch",
         "[federation-worker][event-loop][thread-pool]")
{
    GIVEN("a thread pool that has been stopped")
    {
        auto pool = ThreadPool{1U};
        auto ran = std::atomic<bool>{false};
        REQUIRE(pool.submit([&] {
            ran.store(true);
        }));
        std::this_thread::sleep_for(std::chrono::milliseconds{50});
        pool.request_stop();

        WHEN("another work item is submitted")
        {
            THEN("submit returns false so the caller can send an error response instead of dropping the request")
            {
                REQUIRE_FALSE(pool.submit([&] {
                    ran.store(true);
                }));
            }
        }
    }
}
