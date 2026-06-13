// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/persistent_store.hpp"
#include "merovingian/federation/outbound_transaction.hpp"
#include "merovingian/federation/server_discovery.hpp"
#include "merovingian/http/outbound_client.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace merovingian::federation
{

// Snapshot of a destination's retry state. The dispatch worker keeps these
// in memory keyed by server_name so it can short-circuit through the
// existing destination_should_retry circuit breaker between attempts.
struct DispatchDestinationSnapshot final
{
    std::string server_name{};
    FederationDestination state{};
};

// Wall-clock millisecond source. Injectable so deterministic tests can drive
// retry boundaries without sleeping.
using DispatchClock = std::function<std::uint64_t()>;

// Sleep hook used by the worker between idle polls and inside retry waits.
// Injectable so tests can intercept and avoid real sleeps. Default is
// std::this_thread::sleep_for.
using DispatchSleep = std::function<void(std::chrono::milliseconds)>;

// Discovery short-circuit: production wires this to the cached
// ServerDiscoveryNetwork-backed discoverer; tests can supply a
// deterministic resolver that returns synthetic addresses.
using DispatchResolver = std::function<std::optional<ServerDiscoveryResult>(std::string_view server_name)>;

struct DispatchWorkerConfig final
{
    // Identity used when signing outbound traffic. The signing identity
    // mirrors the runtime's persisted Ed25519 signing key. `secret_key` is
    // the raw 64-byte libsodium Ed25519 secret key.
    std::string origin{};
    std::string key_id{};
    std::string secret_key{};
    // Bound on the in-memory enqueue list. Enforced fail-closed: enqueue
    // returns false once the limit is hit. Zero disables the bound for tests.
    std::size_t max_queue_depth{1024U};
    // Maximum number of retry attempts before a transaction is dropped and
    // recorded as terminally failed. Matches the federation backoff curve.
    std::uint32_t max_retries{8U};
    // How long the worker sleeps when the queue is empty before re-checking
    // for shutdown. Smaller values shorten shutdown latency.
    std::chrono::milliseconds idle_poll{std::chrono::milliseconds{50}};
};

struct DispatchWorkerSummary final
{
    std::size_t enqueued{0U};
    std::size_t delivered{0U};
    std::size_t failed{0U};
    std::size_t dropped{0U};
    std::size_t pending{0U};
};

// Federation outbound dispatch worker.
//
// Lifecycle:
//   - `enqueue` and the worker thread are safe to use concurrently.
//   - `start` spawns one background thread that drains the queue.
//   - `request_shutdown` signals the loop to stop pulling new work and to
//     exit after the in-flight attempt completes. The remaining queue is
//     left intact; persisted queue rows can be replayed by the next worker.
//   - `drain` is the cooperative variant: the loop keeps pulling until the
//     queue is empty *and* shutdown has been requested. Tests use this to
//     synchronize against a known set of enqueues.
//   - The destructor calls request_shutdown + join. Constructing the worker
//     does not start the thread; runtime owners call `start` explicitly.
//
// Safety:
//   - The worker owns its mutex/condition_variable and never exposes them.
//   - All injected callbacks are invoked from the worker thread; callers
//     must keep referenced resources (OutboundClient, store, etc.) alive
//     until the worker is joined.
class DispatchWorker final
{
public:
    DispatchWorker(DispatchWorkerConfig config, http::OutboundClient& client, DispatchResolver resolver,
                   DispatchClock now_ms, DispatchSleep sleep_for,
                   database::PersistentStore* persistent_store = nullptr);
    ~DispatchWorker();

    DispatchWorker(DispatchWorker const&) = delete;
    auto operator=(DispatchWorker const&) -> DispatchWorker& = delete;
    DispatchWorker(DispatchWorker&&) noexcept = delete;
    auto operator=(DispatchWorker&&) noexcept -> DispatchWorker& = delete;

    // Adds a transaction to the pending queue. Returns false if the queue
    // is at capacity, the worker has shut down, or the transaction is
    // malformed (missing transaction id, destination, target, origin, or body).
    [[nodiscard]] auto enqueue(OutboundTransaction transaction) -> bool;

    auto start() -> void;
    auto request_shutdown() noexcept -> void;
    auto join() -> void;

    // Drives one full dispatch attempt in the calling thread. Returns true
    // when the queue was non-empty (and one item was processed) and false
    // when the queue was empty. Exposed for deterministic tests; the worker
    // thread uses the same path internally.
    [[nodiscard]] auto run_once() -> bool;

    [[nodiscard]] auto replay_pending() -> std::size_t;
    [[nodiscard]] auto summary() const noexcept -> DispatchWorkerSummary;

private:
    auto loop() -> void;
    auto take_next(OutboundTransaction& out) -> bool;
    auto re_enqueue_with_backoff(OutboundTransaction transaction, std::uint64_t now_ts) -> void;
    auto find_or_create_destination(std::string_view server_name) -> FederationDestination&;
    // Promote replay-overflow rows into the active queue while capacity allows.
    // Caller must hold mutex_. Returns the number of rows promoted.
    auto top_up_replay_locked() -> std::size_t;

    DispatchWorkerConfig config_{};
    http::OutboundClient& client_;
    DispatchResolver resolver_{};
    DispatchClock now_ms_{};
    DispatchSleep sleep_for_{};
    database::PersistentStore* persistent_store_{nullptr};

    mutable std::mutex mutex_{};
    std::condition_variable cv_{};
    std::deque<OutboundTransaction> queue_{};
    // Durable rows that didn't fit under max_queue_depth at replay time.
    // Drained into queue_ as in-flight work completes so backlog larger than
    // the in-memory cap is not stranded until the next restart.
    std::deque<OutboundTransaction> pending_replay_{};
    std::vector<DispatchDestinationSnapshot> destinations_{};
    DispatchWorkerSummary summary_{};

    std::atomic<bool> shutdown_requested_{false};
    std::atomic<bool> started_{false};
    std::thread thread_{};
};

} // namespace merovingian::federation
