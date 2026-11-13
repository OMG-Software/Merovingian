// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/core/SecretBuffer.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/federation/DispatchDestinationSnapshot.hpp"
#include "merovingian/federation/DispatchWorkerConfig.hpp"
#include "merovingian/federation/DispatchWorkerSummary.hpp"
#include "merovingian/federation/FederationDestination.hpp"
#include "merovingian/federation/OutboundTransaction.hpp"
#include "merovingian/federation/ServerDiscoveryResult.hpp"
#include "merovingian/http/OutboundClient.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace merovingian::federation
{

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

// The most that discovery may take on a delivery thread (F-20, ADR-0354). The runtime's general remote
// timeout is for other callers; discovery here runs before an attempt has even started.
inline constexpr auto dispatch_discovery_timeout_seconds = std::uint32_t{10U};

// The per-destination bound a worker with `config` enforces: max_pending_per_destination when set,
// otherwise a sixteenth of max_queue_depth and never below 16 (256 for the default 4096).
[[nodiscard]] auto effective_max_pending_per_destination(DispatchWorkerConfig const& config) noexcept -> std::size_t;

// The most slots destinations that are failing may hold between them (ADR-0621):
// max_pending_failing_destinations when set, otherwise half of max_queue_depth and at least 1. An unbounded
// queue has no such limit.
[[nodiscard]] auto effective_max_pending_failing(DispatchWorkerConfig const& config) noexcept -> std::size_t;

// Federation outbound dispatch worker.
//
// Lifecycle:
//   - `enqueue` and the worker thread are safe to use concurrently.
//   - `start` spawns config.delivery_threads background threads that drain
//     the queue. A destination has at most one transaction in flight, and
//     only its oldest can be taken, so one destination occupies at most one
//     thread and its transactions keep their order (ADR-0354).
//   - `request_shutdown` signals the loop to stop pulling new work and to
//     exit after the in-flight attempts complete and the shutdown drain has
//     had its budget. The remaining queue is left intact; persisted queue rows
//     can be replayed by the next worker.
//     It takes the worker's mutex (ADR-0312), so never call it from an
//     injected callback: the clock runs inside the idle wait with it held.
//   - `drain` is the cooperative variant: the loop keeps pulling until the
//     queue is empty *and* shutdown has been requested. Tests use this to
//     synchronize against a known set of enqueues.
//   - The destructor calls request_shutdown + join. Constructing the worker
//     does not start the thread; runtime owners call `start` explicitly.
//
// Safety:
//   - The worker owns its mutex/condition_variable and never exposes them.
//   - All injected callbacks are invoked from the worker threads, at the same
//     time when delivery_threads is above one, so they must be safe to call
//     concurrently; callers must keep referenced resources (OutboundClient,
//     store, etc.) alive until the worker is joined.
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
    // Enqueues the transactions of one event, one per destination, and commits their durable rows in a single
    // transaction (ADR-0441). Each is admitted or refused by the same checks as `enqueue`, counting the batch's
    // earlier members against the depth and the destination's share. Answers one flag per transaction, in order.
    // If the commit fails, none of the admitted transactions is queued or stored and every one answers false.
    [[nodiscard]] auto enqueue_batch(std::vector<OutboundTransaction> batch) -> std::vector<bool>;

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

    // Key id the worker currently signs outbound traffic with.
    [[nodiscard]] auto signing_key_id() const -> std::string;

    // Replaces the signing identity used for subsequent attempts. The worker
    // snapshots the server signing key when it is constructed, so without this a
    // key rotation leaves it signing with the retired key while the rest of the
    // runtime has moved on — peers then reject every transaction it sends. Safe to
    // call while the worker thread is running; an attempt already in flight
    // completes with the identity it started with.
    auto update_signing_identity(std::string key_id, core::SecretBuffer secret_key) -> void;

private:
    // Holds a destination's place as in flight for the length of one attempt, and wakes the other
    // threads when it ends: the destination's next transaction may now be taken.
    class InFlightSlot final
    {
    public:
        InFlightSlot(DispatchWorker& worker, std::string destination) noexcept;
        ~InFlightSlot();

        InFlightSlot(InFlightSlot const&) = delete;
        auto operator=(InFlightSlot const&) -> InFlightSlot& = delete;
        InFlightSlot(InFlightSlot&&) = delete;
        auto operator=(InFlightSlot&&) -> InFlightSlot& = delete;

    private:
        DispatchWorker& worker_;
        std::string destination_;
    };

    auto loop() -> void;
    // One attempt of a transaction due by `due_by` (ADR-0309): run_once passes now; the shutdown drain
    // passes the moment it started, so a transaction that fails during the drain waits for replay.
    [[nodiscard]] auto run_due(std::uint64_t due_by) -> bool;
    auto attempt(OutboundTransaction transaction) -> void;
    // A transaction whose destination is backing off waits for it, without taking a discovery or a
    // network call.
    auto wait_out_open_circuit(OutboundTransaction transaction, FederationDestination const& destination,
                               std::uint64_t now_ts) -> void;
    auto take_next(OutboundTransaction& out, std::uint64_t due_by) -> bool;
    // The position in queue_ of the next transaction that may go, or nullopt. A destination offers
    // only its oldest, and only with nothing in flight. Spec (Server-Server API, PUT /send/{txnId}):
    // "The sending server must wait and retry for a 200 OK response before sending a transaction
    // with a different txnId to the receiving server." Call with mutex_ held.
    [[nodiscard]] auto next_ready_locked(std::uint64_t due_by) const -> std::optional<std::size_t>;
    auto re_enqueue_with_backoff(OutboundTransaction transaction, std::uint64_t now_ts) -> void;
    // Attempts work on a copy of a destination's state and put it back here: only one attempt per
    // destination runs at a time, and destinations_ can reallocate while it does. Call with mutex_
    // held.
    auto find_or_create_destination(std::string_view server_name) -> FederationDestination&;
    auto remember_destination_locked(FederationDestination const& destination) -> void;
    // Promote replay-overflow rows into the active queue while capacity allows.
    // Caller must hold mutex_. Returns the number of rows promoted.
    auto top_up_replay_locked() -> std::size_t;
    // A destination's slots count its queued AND in-flight transactions: a slot is taken when a
    // transaction is admitted (push_queue_locked), kept while the worker attempts it and while it
    // waits to retry (requeue_locked), and released only when it leaves for good: delivered,
    // dropped, or failed to persist (release_destination_slot_locked). So a concurrent enqueue
    // cannot take an in-flight transaction's slot. Caller must hold mutex_.
    auto push_queue_locked(OutboundTransaction transaction) -> void;
    auto requeue_locked(OutboundTransaction transaction) -> void;
    auto release_destination_slot_locked(std::string const& destination) -> void;
    [[nodiscard]] auto destination_at_share_locked(std::string const& destination) const -> bool;
    // Whether `destination` is backing off with the failing destinations' share spent, `taken` slots counted beyond
    // those already held. A failing destination past its backoff is never refused: it is due a try. Caller holds
    // mutex_.
    [[nodiscard]] auto failing_share_reached_locked(std::string const& destination, std::uint64_t now,
                                                    std::size_t taken) const -> bool;
    // Drops the entries at ascending `queued` and `parked` positions for good, with one durable commit; if that
    // fails they all stay. Caller must hold mutex_.
    auto discard_locked(std::vector<std::size_t> const& queued, std::vector<std::size_t> const& parked,
                        std::string_view reason) -> void;
    // Brings the failing destinations back within their share (ADR-0621): each keeps its oldest transactions, and the
    // largest holders give up their newest. Caller must hold mutex_.
    auto shed_failing_over_share_locked() -> void;
    // Drops failing destinations' transactions past max_failing_transaction_age_ms, at most once per
    // age_sweep_interval_ms. Caller must hold mutex_.
    auto sweep_aged_locked(std::uint64_t now) -> void;
    // Marks a destination that answers, but slowly, or clears the mark (C20, ADR-0720). A slow destination keeps the
    // rows already queued for it, but its new rows are refused once the slow destinations hold their share, and its
    // rows go after every other destination's. Keeps slow_slots_ equal to the sum of the marked destinations' entries
    // in queued_per_destination_. Caller must hold mutex_.
    auto set_slow_locked(std::string const& destination, bool slow) -> void;

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
    // Slots held per destination: transactions in queue_ or in flight (not pending_replay_),
    // guarded by mutex_.
    std::unordered_map<std::string, std::size_t> queued_per_destination_{};
    // Destinations with an attempt running, guarded by mutex_.
    std::set<std::string, std::less<>> in_flight_destinations_{};
    // Destinations whose last attempt failed, each with when its backoff ends, and the slots they hold between them
    // (ADR-0621), guarded by mutex_. Changed only by remember_destination_locked and replay_pending; the slot
    // bookkeeping above keeps failing_slots_ equal to the sum of these destinations' entries in
    // queued_per_destination_.
    std::unordered_map<std::string, std::uint64_t> failing_destinations_{};
    std::size_t failing_slots_{0U};
    // Destinations that deliver, but slowly: the last attempt took more than a quarter of slow_attempt_ms (C20,
    // ADR-0720), and the slots they hold between them. Disjoint from failing_destinations_. A destination leaves the
    // set when a quicker attempt follows, when it starts to fail, or when its last slot is released, so the set is
    // bounded by the destinations that hold a slot. Guarded by mutex_.
    std::unordered_set<std::string> slow_destinations_{};
    std::size_t slow_slots_{0U};
    // The next time sweep_aged_locked looks at the queue, guarded by mutex_.
    std::uint64_t next_age_sweep_ms_{0U};
    std::vector<DispatchDestinationSnapshot> destinations_{};
    DispatchWorkerSummary summary_{};

    std::atomic<bool> shutdown_requested_{false};
    std::atomic<bool> started_{false};
    std::vector<std::thread> threads_{};
    // What the shutdown drain covers and when it ends, set by the first thread to reach it, so a thread
    // finishing a long attempt does not re-try what another thread failed during the drain. Guarded by
    // mutex_.
    std::optional<std::uint64_t> drain_due_by_{};
    std::chrono::steady_clock::time_point drain_deadline_{};
};

} // namespace merovingian::federation
