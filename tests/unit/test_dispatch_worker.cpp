// SPDX-License-Identifier: GPL-3.0-or-later

#include "../support/joining_threads.hpp"
#include "../support/tls_mock_server.hpp"
#include "federation_signing_test_support.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/federation/dispatch_worker.hpp"
#include "merovingian/federation/outbound_transaction.hpp"
#include "merovingian/federation/server_discovery.hpp"
#include "merovingian/homeserver/tls.hpp"
#include "merovingian/http/outbound_client.hpp"
#include "merovingian/net/tcp_acceptor.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <latch>
#include <memory>
#include <optional>
#include <semaphore>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>

namespace
{

[[nodiscard]] auto sample_transaction(std::string destination) -> merovingian::federation::OutboundTransaction
{
    auto transaction = merovingian::federation::OutboundTransaction{};
    transaction.transaction_id = "txn-1";
    transaction.destination = std::move(destination);
    transaction.method = "PUT";
    transaction.target = "/_matrix/federation/v1/send/txn-1";
    transaction.origin = "origin.example.org";
    transaction.body = R"({"pdus":[]})";
    return transaction;
}

[[nodiscard]] auto worker_config() -> merovingian::federation::DispatchWorkerConfig
{
    auto config = merovingian::federation::DispatchWorkerConfig{};
    config.origin = "origin.example.org";
    config.key_id = "ed25519:auto";
    config.secret_key = merovingian::federation::test::secret_key_buffer(
        merovingian::federation::test::keypair_from_seed("deterministic-test-token"));
    config.max_queue_depth = 16U;
    config.max_retries = 3U;
    config.idle_poll = std::chrono::milliseconds{5};
    return config;
}

} // namespace

SCENARIO("Dispatch worker rejects malformed transactions at enqueue time", "[federation][dispatch-worker][enqueue]")
{
    GIVEN("a dispatch worker bound to a real OutboundClient instance")
    {
        auto client = merovingian::http::OutboundClient{};
        auto resolver = merovingian::federation::DispatchResolver{[](std::string_view) {
            return std::optional<merovingian::federation::ServerDiscoveryResult>{};
        }};
        auto worker = merovingian::federation::DispatchWorker{worker_config(), client, std::move(resolver), {}, {}};

        WHEN("a transaction without destination is enqueued")
        {
            auto transaction = sample_transaction("");

            THEN("enqueue fails closed and the summary is empty")
            {
                REQUIRE_FALSE(worker.enqueue(transaction));
                auto const summary = worker.summary();
                REQUIRE(summary.enqueued == 0U);
                REQUIRE(summary.pending == 0U);
            }
        }
    }
}

SCENARIO("Dispatch worker re-enqueues when discovery fails and stops after max retries",
         "[federation][dispatch-worker][retry]")
{
    GIVEN("a worker whose resolver always reports discovery failure")
    {
        auto client = merovingian::http::OutboundClient{};
        // Resolver returns nullopt: run_once never touches the OutboundClient
        // for this path, so the test stays hermetic.
        auto resolver = merovingian::federation::DispatchResolver{[](std::string_view) {
            return std::optional<merovingian::federation::ServerDiscoveryResult>{};
        }};
        auto fake_now = std::make_shared<std::atomic<std::uint64_t>>(0U);
        auto now_ms = merovingian::federation::DispatchClock{[fake_now] {
            return fake_now->load();
        }};
        auto config = worker_config();
        config.max_retries = 3U;
        auto worker = merovingian::federation::DispatchWorker{
            std::move(config), client, std::move(resolver), std::move(now_ms), {}};

        WHEN("a transaction is enqueued and run_once is driven explicitly")
        {
            REQUIRE(worker.enqueue(sample_transaction("remote.example.org")));

            THEN("the worker re-queues with backoff, advancing the retry counter each pass")
            {
                // Drive enough attempts to hit the max retry limit. Advance the
                // injected clock past each backoff so the retry-deadline filter
                // lets the next attempt through.
                for (auto attempt = 0U; attempt < 5U; ++attempt)
                {
                    fake_now->store(fake_now->load() + 600000ULL);
                    std::ignore = worker.run_once();
                }
                auto const summary = worker.summary();
                REQUIRE(summary.failed >= 1U);
                REQUIRE(summary.dropped >= 1U);
                REQUIRE(summary.pending == 0U);
            }
        }
    }
}

SCENARIO("Dispatch worker re-enqueues transactions when the destination circuit is open",
         "[federation][dispatch-worker][retry]")
{
    GIVEN("a worker with an open destination circuit and queued work")
    {
        auto client = merovingian::http::OutboundClient{};
        auto fake_now = std::make_shared<std::atomic<std::uint64_t>>(0U);
        auto resolver_allows = std::make_shared<std::atomic_bool>(false);
        auto resolver = merovingian::federation::DispatchResolver{[resolver_allows](std::string_view server_name) {
            if (!resolver_allows->load())
            {
                return std::optional<merovingian::federation::ServerDiscoveryResult>{};
            }
            auto discovery = merovingian::federation::ServerDiscoveryResult{};
            discovery.server_name = std::string{server_name};
            discovery.resolved_host = std::string{server_name};
            discovery.resolved_port = 8448U;
            discovery.pinned_addresses = {"203.0.113.10"};
            discovery.discovery_allowed = true;
            return std::optional<merovingian::federation::ServerDiscoveryResult>{std::move(discovery)};
        }};
        auto now_ms = merovingian::federation::DispatchClock{[fake_now] {
            return fake_now->load();
        }};
        auto config = worker_config();
        config.max_retries = 8U;
        auto worker = merovingian::federation::DispatchWorker{
            std::move(config), client, std::move(resolver), std::move(now_ms), {}};

        WHEN("prior failures open the circuit before another transaction is ready")
        {
            REQUIRE(worker.enqueue(sample_transaction("remote.example.org")));
            for (auto attempt = 0U; attempt < 3U; ++attempt)
            {
                fake_now->store(fake_now->load() + 600000ULL);
                REQUIRE(worker.run_once());
            }
            resolver_allows->store(true);
            auto second = sample_transaction("remote.example.org");
            second.transaction_id = "txn-2";
            REQUIRE(worker.enqueue(std::move(second)));
            // Spec (Server-Server API, PUT /send/{txnId}): "must wait and retry for a 200 OK response before sending a
            // transaction with a different txnId". The later one waits behind the one in backoff.
            REQUIRE_FALSE(worker.run_once());

            THEN("both stay pending for retry instead of being discarded")
            {
                auto const summary = worker.summary();
                REQUIRE(summary.failed == 3U);
                REQUIRE(summary.pending == 2U);
                REQUIRE(summary.dropped == 0U);
            }
        }
    }
}

SCENARIO("Dispatch worker replays persisted queue rows with destination retry state",
         "[federation][dispatch-worker][persistence]")
{
    GIVEN("a persistent store with a pending transaction and open destination circuit")
    {
        auto opened = merovingian::database::open_persistent_store();
        REQUIRE(opened.ok);
        auto& store = opened.store;
        REQUIRE(merovingian::database::store_federation_destination(
            store, {"remote.example.org", "backoff", 5000U, 1000U, 3U}));
        REQUIRE(merovingian::database::store_federation_transaction(
            store, {"txn-1", "remote.example.org", "PUT", "/_matrix/federation/v1/send/txn-1", "origin.example.org",
                    "1234", R"({"pdus":[]})", 1U, 0U}));

        auto client = merovingian::http::OutboundClient{};
        auto resolver = merovingian::federation::DispatchResolver{[](std::string_view server_name) {
            auto discovery = merovingian::federation::ServerDiscoveryResult{};
            discovery.server_name = std::string{server_name};
            discovery.resolved_host = std::string{server_name};
            discovery.resolved_port = 8448U;
            discovery.pinned_addresses = {"203.0.113.10"};
            discovery.discovery_allowed = true;
            return std::optional<merovingian::federation::ServerDiscoveryResult>{std::move(discovery)};
        }};
        auto fake_now = std::make_shared<std::atomic<std::uint64_t>>(2000U);
        auto now_ms = merovingian::federation::DispatchClock{[fake_now] {
            return fake_now->load();
        }};
        auto config = worker_config();
        auto worker = merovingian::federation::DispatchWorker{std::move(config), client, std::move(resolver),
                                                              std::move(now_ms), {},     &store};

        WHEN("the worker replays persisted rows after restart and runs before backoff expires")
        {
            auto const replayed = worker.replay_pending();
            auto const ran = worker.run_once();

            THEN("the pending transaction remains queued using the persisted circuit deadline")
            {
                REQUIRE(replayed == 1U);
                REQUIRE(ran);
                auto const summary = worker.summary();
                REQUIRE(summary.enqueued == 1U);
                REQUIRE(summary.failed == 1U);
                REQUIRE(summary.pending == 1U);
                REQUIRE(store.federation_transactions.size() == 1U);
                REQUIRE(store.federation_transactions.front().next_retry_ts == 5000U);
                REQUIRE(store.federation_destinations.front().consecutive_failures == 3U);
            }
        }
    }
}

SCENARIO("Dispatch worker keeps replay overflow durable and drains it as queue space frees up",
         "[federation][dispatch-worker][persistence]")
{
    GIVEN("a persistent store holding more pending rows than the worker's max queue depth")
    {
        auto opened = merovingian::database::open_persistent_store();
        REQUIRE(opened.ok);
        auto& store = opened.store;
        // Two pending rows, max_queue_depth == 1. The first row goes into the
        // active queue; the second must be parked in pending_replay_ and
        // promoted as soon as the active queue drains. Both have already
        // exhausted their retry deadline (next_retry_ts == 0).
        REQUIRE(merovingian::database::store_federation_transaction(
            store, {"txn-1", "remote.example.org", "PUT", "/_matrix/federation/v1/send/txn-1", "origin.example.org",
                    "1234", R"({"pdus":[]})", 0U, 0U}));
        REQUIRE(merovingian::database::store_federation_transaction(
            store, {"txn-2", "remote.example.org", "PUT", "/_matrix/federation/v1/send/txn-2", "origin.example.org",
                    "1234", R"({"pdus":[]})", 0U, 0U}));

        auto client = merovingian::http::OutboundClient{};
        auto resolver = merovingian::federation::DispatchResolver{[](std::string_view) {
            // Resolver always reports discovery failure: run_once never touches
            // the OutboundClient and the transactions cycle back through
            // re_enqueue_with_backoff, which drops them at max_retries.
            return std::optional<merovingian::federation::ServerDiscoveryResult>{};
        }};
        auto fake_now = std::make_shared<std::atomic<std::uint64_t>>(0U);
        auto now_ms = merovingian::federation::DispatchClock{[fake_now] {
            return fake_now->load();
        }};
        auto config = worker_config();
        config.max_queue_depth = 1U;
        config.max_retries = 1U;
        auto worker = merovingian::federation::DispatchWorker{std::move(config), client, std::move(resolver),
                                                              std::move(now_ms), {},     &store};

        WHEN("the worker replays and drains the active queue")
        {
            auto const replayed = worker.replay_pending();
            // First run drops txn-1 (one retry past max). Removing it frees
            // a queue slot which top_up_replay_locked() must promote with the
            // parked overflow row before run_once returns.
            fake_now->store(600000ULL);
            auto const first_run = worker.run_once();
            fake_now->store(1200000ULL);
            auto const second_run = worker.run_once();

            THEN("the overflow row is promoted from durable storage as space frees")
            {
                REQUIRE(replayed == 1U);
                REQUIRE(first_run);
                REQUIRE(second_run);
                auto const summary = worker.summary();
                // Both rows were enqueued (one at replay, one promoted) and
                // both terminally dropped after max_retries.
                REQUIRE(summary.enqueued == 2U);
                REQUIRE(summary.dropped == 2U);
                REQUIRE(summary.pending == 0U);
                REQUIRE(store.federation_transactions.empty());
            }
        }
    }
}

SCENARIO("Dispatch worker respects shutdown after drain", "[federation][dispatch-worker][shutdown]")
{
    GIVEN("a worker thread driving a queue with one persistently failing transaction")
    {
        auto client = merovingian::http::OutboundClient{};
        auto resolver = merovingian::federation::DispatchResolver{[](std::string_view) {
            return std::optional<merovingian::federation::ServerDiscoveryResult>{};
        }};
        auto fake_now = std::make_shared<std::atomic<std::uint64_t>>(0U);
        auto now_ms = merovingian::federation::DispatchClock{[fake_now] {
            fake_now->fetch_add(600000ULL);
            return fake_now->load();
        }};
        auto sleep_for =
            merovingian::federation::DispatchSleep{[](std::chrono::milliseconds) { /* no real sleep in tests */ }};
        auto config = worker_config();
        config.max_retries = 2U;
        auto worker = merovingian::federation::DispatchWorker{std::move(config), client, std::move(resolver),
                                                              std::move(now_ms), std::move(sleep_for)};

        WHEN("the worker thread starts, processes the queue, and is asked to shut down")
        {
            REQUIRE(worker.enqueue(sample_transaction("remote.example.org")));
            worker.start();
            worker.request_shutdown();
            worker.join();

            THEN("the worker exits, and the transaction was attempted and either dropped or kept for replay")
            {
                // How many attempts run before the thread sees the shutdown is a race; the drain then
                // tries what was due once and keeps a failure for replay (ADR-0309), so it ends.
                auto const summary = worker.summary();
                REQUIRE(summary.enqueued >= 1U);
                REQUIRE(summary.failed >= 1U);
                REQUIRE(summary.dropped + summary.pending == 1U);
            }
        }
    }
}

SCENARIO("Dispatch worker shutdown wakes an idle worker that is checking its wait condition",
         "[federation][dispatch-worker][shutdown][shutdown-wakeup]")
{
    // The idle wait checks "shutdown requested, or a transaction is due" and then blocks. A
    // shutdown request that set the flag and notified between that check and the block was lost,
    // and the worker slept for the whole idle poll. The clock is read inside that check, so the
    // test requests shutdown from there.
    GIVEN("an idle worker with a long idle poll whose clock asks for shutdown from inside the wait check")
    {
        auto client = merovingian::http::OutboundClient{};
        auto resolver = merovingian::federation::DispatchResolver{[](std::string_view) {
            return std::optional<merovingian::federation::ServerDiscoveryResult>{};
        }};
        auto in_wait_check = std::make_shared<std::latch>(1);
        auto shutdown_requested = std::make_shared<std::binary_semaphore>(0);
        auto clock_reads = std::make_shared<std::atomic<int>>(0);
        // With an empty queue the first read is run_once's and the second is the wait check's.
        auto now_ms = merovingian::federation::DispatchClock{[in_wait_check, shutdown_requested, clock_reads] {
            if (clock_reads->fetch_add(1) + 1 == 2)
            {
                in_wait_check->count_down();
                // Give the request time to land while the check is running. A request that
                // waits for the worker's lock cannot finish yet, so this times out.
                std::ignore = shutdown_requested->try_acquire_for(std::chrono::milliseconds{500});
            }
            return std::uint64_t{0U};
        }};
        auto sleep_for =
            merovingian::federation::DispatchSleep{[](std::chrono::milliseconds) { /* no real sleep in tests */ }};
        auto config = worker_config();
        config.idle_poll = std::chrono::seconds{20};
        auto worker = merovingian::federation::DispatchWorker{std::move(config), client, std::move(resolver),
                                                              std::move(now_ms), std::move(sleep_for)};

        WHEN("shutdown is requested while the worker is checking its wait condition")
        {
            auto const started = std::chrono::steady_clock::now();
            worker.start();
            {
                auto requester = merovingian::tests::JoiningThreads{};
                requester.emplace_back([&worker, in_wait_check, shutdown_requested] {
                    in_wait_check->wait();
                    worker.request_shutdown();
                    shutdown_requested->release();
                });
                worker.join();
            }
            auto const elapsed = std::chrono::steady_clock::now() - started;

            THEN("the worker stops well within one idle poll")
            {
                CHECK(elapsed < std::chrono::seconds{10});
            }
        }
    }
}

SCENARIO("Dispatch worker start is idempotent — calling start twice does not spawn a second thread",
         "[federation][dispatch-worker][start]")
{
    GIVEN("a running worker with an immediate-shutdown resolver")
    {
        auto client = merovingian::http::OutboundClient{};
        auto resolver = merovingian::federation::DispatchResolver{[](std::string_view) {
            return std::optional<merovingian::federation::ServerDiscoveryResult>{};
        }};
        auto sleep_for =
            merovingian::federation::DispatchSleep{[](std::chrono::milliseconds) { /* no real sleep in tests */ }};
        auto worker = merovingian::federation::DispatchWorker{
            worker_config(), client, std::move(resolver), {}, std::move(sleep_for)};

        WHEN("start() is called twice before shutdown")
        {
            worker.start();
            worker.start(); // must not throw or spawn a second thread
            worker.request_shutdown();
            worker.join();

            THEN("the worker exits cleanly — no crash, no double-join hang, summary is accessible")
            {
                auto const summary = worker.summary();
                REQUIRE(summary.enqueued == 0U);
            }
        }
    }
}

SCENARIO("Dispatch worker enforces queue depth", "[federation][dispatch-worker][bounds]")
{
    GIVEN("a worker with a queue depth of 2")
    {
        auto client = merovingian::http::OutboundClient{};
        auto resolver = merovingian::federation::DispatchResolver{[](std::string_view) {
            return std::optional<merovingian::federation::ServerDiscoveryResult>{};
        }};
        auto config = worker_config();
        config.max_queue_depth = 2U;
        auto worker = merovingian::federation::DispatchWorker{std::move(config), client, std::move(resolver), {}, {}};

        WHEN("three transactions are enqueued without draining")
        {
            auto const first = worker.enqueue(sample_transaction("remote.example.org"));
            auto const second = worker.enqueue(sample_transaction("remote.example.org"));
            auto const third = worker.enqueue(sample_transaction("remote.example.org"));

            THEN("the bound is enforced and the third enqueue fails closed")
            {
                REQUIRE(first);
                REQUIRE(second);
                REQUIRE_FALSE(third);
                auto const summary = worker.summary();
                REQUIRE(summary.enqueued == 2U);
                REQUIRE(summary.pending == 2U);
            }
        }
    }
}

// Merovingian invariant (signing identity follows rotation):
// The worker snapshots the server signing key when it is constructed. After a
// key rotation the rest of the runtime signs with the new key while the worker
// would still be holding the retired one, and peers reject every transaction
// signed with a key published under old_verify_keys with a past expired_ts. The
// identity must therefore be replaceable on a live worker.
SCENARIO("Dispatch worker signing identity can be replaced after construction",
         "[federation][dispatch-worker][signing]")
{
    GIVEN("a dispatch worker constructed with an initial signing identity")
    {
        auto client = merovingian::http::OutboundClient{};
        auto resolver = merovingian::federation::DispatchResolver{[](std::string_view) {
            return std::optional<merovingian::federation::ServerDiscoveryResult>{};
        }};
        auto worker = merovingian::federation::DispatchWorker{worker_config(), client, std::move(resolver), {}, {}};
        REQUIRE(worker.signing_key_id() == "ed25519:auto");

        WHEN("a rotated identity is handed to the worker")
        {
            auto rotated_secret = merovingian::federation::test::secret_key_buffer(
                merovingian::federation::test::keypair_from_seed("rotated-test-token"));
            worker.update_signing_identity("ed25519:b1656160", std::move(rotated_secret));

            THEN("subsequent traffic is attributed to the new key id")
            {
                REQUIRE(worker.signing_key_id() == "ed25519:b1656160");
            }

            AND_THEN("the worker still accepts and queues transactions")
            {
                // The update must not disturb queue state: an identity swap is not a
                // reason to start dropping traffic.
                REQUIRE(worker.enqueue(sample_transaction("remote.example.org")));
                auto const summary = worker.summary();
                REQUIRE(summary.enqueued == 1U);
                REQUIRE(summary.pending == 1U);
            }
        }
    }
}

// Security audit run-1 (fed.outbound-fanout-unbounded-destinations-queue-poison): every destination
// shares one queue bound. A destination whose circuit is open keeps its transactions queued
// (circuit_open re-queues without counting a retry), so one dead or hostile peer could fill the
// queue and every other peer's transactions were then refused. Each destination now holds at most
// its share of the queue; past it the transaction is refused and counted, and the peer recovers the
// missed events itself (prev_events, /get_missing_events) once it is reachable.
SCENARIO("Dispatch worker limits each destination to its share of the queue",
         "[federation][dispatch-worker][bounds][security]")
{
    GIVEN("a worker with a queue of 64 and a share of 2 per destination")
    {
        auto client = merovingian::http::OutboundClient{};
        auto resolver = merovingian::federation::DispatchResolver{[](std::string_view) {
            return std::optional<merovingian::federation::ServerDiscoveryResult>{};
        }};
        auto config = worker_config();
        config.max_queue_depth = 64U;
        config.max_pending_per_destination = 2U;
        auto worker = merovingian::federation::DispatchWorker{std::move(config), client, std::move(resolver), {}, {}};

        WHEN("three transactions are queued for one destination and one for another")
        {
            auto const first = worker.enqueue(sample_transaction("dead.example.org"));
            auto const second = worker.enqueue(sample_transaction("dead.example.org"));
            auto const third = worker.enqueue(sample_transaction("dead.example.org"));
            auto const other = worker.enqueue(sample_transaction("live.example.org"));

            THEN("the third for the full destination is refused and counted, and the other peer is unaffected")
            {
                REQUIRE(first);
                REQUIRE(second);
                REQUIRE_FALSE(third);
                REQUIRE(other);
                auto const summary = worker.summary();
                REQUIRE(summary.enqueued == 3U);
                REQUIRE(summary.rejected == 1U);
            }
        }

        WHEN("a queued transaction for the full destination is taken by the worker")
        {
            REQUIRE(worker.enqueue(sample_transaction("dead.example.org")));
            REQUIRE(worker.enqueue(sample_transaction("dead.example.org")));
            // The resolver fails, so the attempt re-queues the transaction with a retry: the
            // destination still holds two.
            REQUIRE(worker.run_once());

            THEN("the destination's share is still counted, so another is refused")
            {
                REQUIRE_FALSE(worker.enqueue(sample_transaction("dead.example.org")));
                REQUIRE(worker.summary().pending == 2U);
            }
        }
    }

    GIVEN("a worker configured only with the production queue depth")
    {
        auto config = worker_config();
        config.max_queue_depth = 4096U;
        config.max_pending_per_destination = 0U;

        WHEN("its per-destination share is derived")
        {
            THEN("it is a sixteenth of the queue, and never below sixteen")
            {
                REQUIRE(merovingian::federation::effective_max_pending_per_destination(config) == 256U);
                config.max_queue_depth = 16U;
                REQUIRE(merovingian::federation::effective_max_pending_per_destination(config) == 16U);
                config.max_pending_per_destination = 5U;
                REQUIRE(merovingian::federation::effective_max_pending_per_destination(config) == 5U);
            }
        }
    }
}

// A destination's share counts its queued and in-flight transactions: the slot is held while a
// transaction is attempted and while it waits to retry, so a concurrent enqueue cannot take it,
// and it is released only when the transaction leaves for good.
SCENARIO("A destination's queue share is released only when its transaction leaves for good",
         "[federation][dispatch-worker][bounds][security]")
{
    GIVEN("a worker with a share of one per destination that drops a transaction after one failed attempt")
    {
        auto client = merovingian::http::OutboundClient{};
        auto resolver = merovingian::federation::DispatchResolver{[](std::string_view) {
            return std::optional<merovingian::federation::ServerDiscoveryResult>{};
        }};
        auto config = worker_config();
        config.max_pending_per_destination = 1U;
        config.max_retries = 1U;
        auto worker = merovingian::federation::DispatchWorker{std::move(config), client, std::move(resolver), {}, {}};
        REQUIRE(worker.enqueue(sample_transaction("dead.example.org")));
        REQUIRE_FALSE(worker.enqueue(sample_transaction("dead.example.org")));

        WHEN("the worker's attempt fails and the transaction is dropped")
        {
            REQUIRE(worker.run_once());

            THEN("the slot is free again")
            {
                REQUIRE(worker.summary().dropped == 1U);
                REQUIRE(worker.enqueue(sample_transaction("dead.example.org")));
            }
        }
    }
}

// Replay after a restart admits durable rows under the same share. Rows past a destination's share
// are parked, not dropped, and do not hold up rows for other destinations.
SCENARIO("Dispatch worker replays durable rows within each destination's share",
         "[federation][dispatch-worker][persistence][bounds][security]")
{
    GIVEN("durable rows: three for one destination, then one for another, and a share of two")
    {
        auto opened = merovingian::database::open_persistent_store();
        REQUIRE(opened.ok);
        auto& store = opened.store;
        for (auto const* id : {"txn-a", "txn-b", "txn-c"})
        {
            REQUIRE(merovingian::database::store_federation_transaction(
                store, {id, "dead.example.org", "PUT", std::string{"/_matrix/federation/v1/send/"} + id,
                        "origin.example.org", "1234", R"({"pdus":[]})", 0U, 0U}));
        }
        REQUIRE(merovingian::database::store_federation_transaction(
            store, {"txn-d", "live.example.org", "PUT", "/_matrix/federation/v1/send/txn-d", "origin.example.org",
                    "1234", R"({"pdus":[]})", 0U, 0U}));
        auto client = merovingian::http::OutboundClient{};
        auto resolver = merovingian::federation::DispatchResolver{[](std::string_view) {
            return std::optional<merovingian::federation::ServerDiscoveryResult>{};
        }};
        auto config = worker_config();
        config.max_queue_depth = 64U;
        config.max_pending_per_destination = 2U;
        auto worker =
            merovingian::federation::DispatchWorker{std::move(config), client, std::move(resolver), {}, {}, &store};

        WHEN("the rows are replayed")
        {
            auto const replayed = worker.replay_pending();

            THEN("two rows for the first destination and the other destination's row are queued, and one is parked")
            {
                REQUIRE(replayed == 3U);
                REQUIRE(worker.summary().pending == 3U);
                REQUIRE(store.federation_transactions.size() == 4U);
                REQUIRE_FALSE(worker.enqueue(sample_transaction("dead.example.org")));
                REQUIRE(worker.enqueue(sample_transaction("live.example.org")));
            }
        }
    }
}

// ADR-0309: a retry's delay runs from the end of the failed attempt. Counted from its start, an attempt
// slower than the delay (a connection timeout) was due again the moment it failed, so a peer that was
// down for half a minute used up the doubling and was next tried long after it came back.
SCENARIO("A failed attempt is retried only once its backoff has passed after the attempt ended",
         "[federation][dispatch-worker][retry][adr-0309]")
{
    GIVEN("a worker whose destination takes ten seconds to fail")
    {
        auto client = merovingian::http::OutboundClient{};
        auto fake_now = std::make_shared<std::atomic<std::uint64_t>>(0U);
        auto resolver = merovingian::federation::DispatchResolver{[fake_now](std::string_view) {
            fake_now->fetch_add(10000U);
            return std::optional<merovingian::federation::ServerDiscoveryResult>{};
        }};
        auto now_ms = merovingian::federation::DispatchClock{[fake_now] {
            return fake_now->load();
        }};
        auto config = worker_config();
        config.max_retries = 8U;
        auto worker = merovingian::federation::DispatchWorker{
            std::move(config), client, std::move(resolver), std::move(now_ms), {}};
        REQUIRE(worker.enqueue(sample_transaction("remote.example.org")));

        WHEN("the first attempt fails at ten seconds")
        {
            REQUIRE(worker.run_once());

            THEN("the retry waits for the first backoff after the failure, not after the start")
            {
                fake_now->store(12000U);
                REQUIRE_FALSE(worker.run_once());
                fake_now->store(14000U);
                REQUIRE(worker.run_once());
            }
        }
    }
}

// ADR-0309: shutdown must end. The drain finishes what was due when it was asked to stop and keeps the
// rest for replay; a transaction that fails during the drain is not tried again, or a peer that is down
// keeps the process alive until it is killed.
SCENARIO("After shutdown is requested each transaction is attempted at most once",
         "[federation][dispatch-worker][shutdown][adr-0309]")
{
    GIVEN("a worker whose destination always fails, on a clock that makes every retry due at once")
    {
        auto client = merovingian::http::OutboundClient{};
        auto resolver = merovingian::federation::DispatchResolver{[](std::string_view) {
            return std::optional<merovingian::federation::ServerDiscoveryResult>{};
        }};
        auto fake_now = std::make_shared<std::atomic<std::uint64_t>>(0U);
        auto now_ms = merovingian::federation::DispatchClock{[fake_now] {
            return fake_now->fetch_add(600000ULL) + 600000ULL;
        }};
        auto config = worker_config();
        config.max_retries = 5U;
        auto worker = merovingian::federation::DispatchWorker{
            std::move(config), client, std::move(resolver), std::move(now_ms), {}};

        WHEN("a transaction is queued and the worker is started already asked to stop")
        {
            REQUIRE(worker.enqueue(sample_transaction("remote.example.org")));
            worker.request_shutdown();
            worker.start();
            worker.join();

            THEN("it was tried once and is kept for replay, not retried until dropped")
            {
                auto const summary = worker.summary();
                REQUIRE(summary.failed == 1U);
                REQUIRE(summary.dropped == 0U);
                REQUIRE(summary.pending == 1U);
            }
        }
    }
}

// A queue holding only transactions still in backoff gives the worker nothing to do: it waits for the
// next due one or new work, and does not spin on the queue.
SCENARIO("The worker waits rather than spins while every queued transaction is in backoff",
         "[federation][dispatch-worker][idle][adr-0309]")
{
    GIVEN("a running worker whose only transaction failed and waits out its backoff on a stopped clock")
    {
        auto client = merovingian::http::OutboundClient{};
        auto resolver = merovingian::federation::DispatchResolver{[](std::string_view) {
            return std::optional<merovingian::federation::ServerDiscoveryResult>{};
        }};
        auto clock_reads = std::make_shared<std::atomic<std::uint64_t>>(0U);
        auto now_ms = merovingian::federation::DispatchClock{[clock_reads] {
            clock_reads->fetch_add(1U);
            return std::uint64_t{1000U};
        }};
        auto config = worker_config();
        config.max_retries = 8U;
        config.idle_poll = std::chrono::milliseconds{5};
        auto worker = merovingian::federation::DispatchWorker{
            std::move(config), client, std::move(resolver), std::move(now_ms), {}};
        REQUIRE(worker.enqueue(sample_transaction("remote.example.org")));

        WHEN("its first attempt has failed and it idles for 200 ms")
        {
            worker.start();
            // Wait (bounded) until the attempt has failed and the transaction is back in the queue, so the
            // measurement covers the backoff wait and not the time before the first attempt.
            auto const give_up = std::chrono::steady_clock::now() + std::chrono::seconds{5};
            while (std::chrono::steady_clock::now() < give_up &&
                   (worker.summary().failed != 1U || worker.summary().pending != 1U))
            {
                std::this_thread::sleep_for(std::chrono::milliseconds{1});
            }
            auto const attempted = worker.summary().failed == 1U && worker.summary().pending == 1U;
            auto const reads_before = clock_reads->load();
            std::this_thread::sleep_for(std::chrono::milliseconds{200});
            auto const idle_reads = clock_reads->load() - reads_before;
            worker.request_shutdown();
            worker.join();

            THEN("it looked at the clock about once per idle poll, not millions of times")
            {
                REQUIRE(attempted);
                CAPTURE(idle_reads);
                REQUIRE(idle_reads < 1000U);
            }
        }
    }
}

namespace
{

constexpr auto stalled_peer = std::string_view{"stalled.example.org"};
constexpr auto healthy_peer = std::string_view{"healthy.example.org"};

// A resolver that holds the stalled peer's discovery until released, as a peer holding a delivery thread would. Every
// other peer answers at once. Both report no address, so that nothing here reaches the network.
struct StallingPeers final
{
    std::counting_semaphore<64> stalled_entered{0};
    std::counting_semaphore<64> released{0};
    std::counting_semaphore<64> healthy_attempted{0};
    std::atomic<std::size_t> stalled_attempts{0U};
    std::atomic<std::size_t> stalled_now{0U};
    std::atomic<std::size_t> stalled_most_at_once{0U};

    [[nodiscard]] auto resolver() -> merovingian::federation::DispatchResolver
    {
        return [this](std::string_view server_name) -> std::optional<merovingian::federation::ServerDiscoveryResult> {
            if (server_name != stalled_peer)
            {
                healthy_attempted.release();
                return std::nullopt;
            }
            ++stalled_attempts;
            auto const now = ++stalled_now;
            auto most = stalled_most_at_once.load();
            while (most < now && !stalled_most_at_once.compare_exchange_weak(most, now))
            {
            }
            stalled_entered.release();
            released.acquire();
            --stalled_now;
            return std::nullopt;
        };
    }
};

// Lets the stalled peer go however the scenario ends. Declared after the worker, so it runs before the worker's
// destructor joins the threads the stall is holding.
class StallRelease final
{
public:
    explicit StallRelease(StallingPeers& peers) noexcept
        : peers_{peers}
    {
    }
    ~StallRelease()
    {
        peers_.released.release(32);
    }

    StallRelease(StallRelease const&) = delete;
    auto operator=(StallRelease const&) -> StallRelease& = delete;
    StallRelease(StallRelease&&) = delete;
    auto operator=(StallRelease&&) -> StallRelease& = delete;

private:
    StallingPeers& peers_;
};

[[nodiscard]] auto transaction_named(std::string id, std::string_view destination)
    -> merovingian::federation::OutboundTransaction
{
    auto transaction = sample_transaction(std::string{destination});
    transaction.target = "/_matrix/federation/v1/send/" + id;
    transaction.transaction_id = std::move(id);
    return transaction;
}

[[nodiscard]] auto stored_retry_count(merovingian::database::PersistentStore const& store, std::string_view id)
    -> std::uint32_t
{
    auto const row = std::ranges::find_if(store.federation_transactions, [id](auto const& candidate) {
        return candidate.transaction_id == id;
    });
    // Fixture: a queued transaction has a durable row.
    REQUIRE(row != store.federation_transactions.end());
    return row->retry_count;
}

[[nodiscard]] auto stored_destination(merovingian::database::PersistentStore const& store, std::string_view server_name)
    -> merovingian::database::PersistentFederationDestination
{
    auto const row = std::ranges::find_if(store.federation_destinations, [server_name](auto const& candidate) {
        return candidate.server_name == server_name;
    });
    // Fixture: an attempted destination has a durable row.
    REQUIRE(row != store.federation_destinations.end());
    return *row;
}

} // namespace

// Security audit run 2, F-20, extending ADR-0177: "One peer must not be able to take the delivery capacity every other
// peer depends on." ADR-0177 bounded how much of the queue a peer holds, not how long it holds the worker.
SCENARIO("A peer that stalls a delivery does not delay any other peer", "[f20][federation][dispatch-worker]")
{
    GIVEN("a worker delivering from more than one thread, with a peer that stalls")
    {
        auto client = merovingian::http::OutboundClient{};
        auto peers = StallingPeers{};
        auto config = worker_config();
        config.delivery_threads = 2U;
        auto worker = merovingian::federation::DispatchWorker{std::move(config), client, peers.resolver(), {}, {}};
        auto const release = StallRelease{peers};

        WHEN("the stalled peer's transaction is queued ahead of a healthy peer's")
        {
            REQUIRE(worker.enqueue(transaction_named("stalled-1", stalled_peer)));
            REQUIRE(worker.enqueue(transaction_named("healthy-1", healthy_peer)));
            worker.start();

            THEN("the healthy peer is attempted while the stalled attempt is still in progress")
            {
                REQUIRE(peers.stalled_entered.try_acquire_for(std::chrono::seconds{30}));
                REQUIRE(peers.healthy_attempted.try_acquire_for(std::chrono::seconds{10}));
                REQUIRE(peers.stalled_now.load() == 1U);
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.19, PUT /_matrix/federation/v1/send/{txnId}
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#put_matrixfederationv1sendtxnid
//
// "The sending server must wait and retry for a 200 OK response before sending a transaction with a different txnId to
// the receiving server."
SCENARIO("One destination has one transaction in flight, and its oldest goes first",
         "[f20][federation][dispatch-worker][conformance]")
{
    GIVEN("a worker with threads to spare and two transactions for a peer that stalls")
    {
        auto client = merovingian::http::OutboundClient{};
        auto peers = StallingPeers{};
        auto config = worker_config();
        config.delivery_threads = 4U;
        auto worker = merovingian::federation::DispatchWorker{std::move(config), client, peers.resolver(), {}, {}};
        auto release = std::optional<StallRelease>{std::in_place, peers};
        REQUIRE(worker.enqueue(transaction_named("stalled-1", stalled_peer)));
        REQUIRE(worker.enqueue(transaction_named("stalled-2", stalled_peer)));
        REQUIRE(worker.enqueue(transaction_named("healthy-1", healthy_peer)));

        WHEN("the worker runs")
        {
            worker.start();
            REQUIRE(peers.stalled_entered.try_acquire_for(std::chrono::seconds{30}));
            REQUIRE(peers.healthy_attempted.try_acquire_for(std::chrono::seconds{30}));

            THEN("the second is not attempted while the first is in flight, though threads are free")
            {
                REQUIRE(peers.stalled_attempts.load() == 1U);
                release.reset();
                worker.request_shutdown();
                worker.join();
                REQUIRE(peers.stalled_most_at_once.load() == 1U);
            }
        }
    }

    GIVEN("a transaction that has failed and is waiting to retry")
    {
        auto opened = merovingian::database::open_persistent_store();
        REQUIRE(opened.ok);
        auto& store = opened.store;
        auto client = merovingian::http::OutboundClient{};
        auto discoveries = std::atomic<std::size_t>{0U};
        auto resolver = merovingian::federation::DispatchResolver{
            [&discoveries](std::string_view) -> std::optional<merovingian::federation::ServerDiscoveryResult> {
                ++discoveries;
                return std::nullopt;
            }};
        auto fake_now = std::atomic<std::uint64_t>{0U};
        auto now_ms = merovingian::federation::DispatchClock{[&fake_now] {
            return fake_now.load();
        }};
        auto config = worker_config();
        config.max_retries = 8U;
        auto worker = merovingian::federation::DispatchWorker{std::move(config), client, std::move(resolver),
                                                              std::move(now_ms), {},     &store};
        REQUIRE(worker.enqueue(transaction_named("first", healthy_peer)));
        REQUIRE(worker.run_once());
        auto const retry_due = stored_destination(store, healthy_peer).retry_after_ts;
        REQUIRE(retry_due > 0U);

        WHEN("a later transaction for the same peer is queued")
        {
            REQUIRE(worker.enqueue(transaction_named("second", healthy_peer)));

            THEN("the later one waits behind it, and the next attempt retries the first")
            {
                fake_now.store(retry_due - 1U);
                // Spec MUST: nothing with a different txnId goes out until the first is answered.
                REQUIRE_FALSE(worker.run_once());
                REQUIRE(discoveries.load() == 1U);
                fake_now.store(retry_due);
                REQUIRE(worker.run_once());
                // Spec MUST: the retry is of the first transaction.
                REQUIRE(stored_retry_count(store, "first") == 2U);
                REQUIRE(stored_retry_count(store, "second") == 0U);
            }
        }
    }
}

SCENARIO("A shutdown does not wait for everything that is due", "[f20][federation][dispatch-worker][shutdown]")
{
    GIVEN("a worker with no time left to drain, and work queued")
    {
        auto client = merovingian::http::OutboundClient{};
        auto attempts = std::atomic<std::size_t>{0U};
        auto resolver = merovingian::federation::DispatchResolver{
            [&attempts](std::string_view) -> std::optional<merovingian::federation::ServerDiscoveryResult> {
                ++attempts;
                return std::nullopt;
            }};
        auto config = worker_config();
        config.delivery_threads = 2U;
        config.shutdown_drain_budget = std::chrono::milliseconds{0};
        auto worker = merovingian::federation::DispatchWorker{std::move(config), client, std::move(resolver), {}, {}};
        REQUIRE(worker.enqueue(transaction_named("one", "one.example.org")));
        REQUIRE(worker.enqueue(transaction_named("two", "two.example.org")));

        WHEN("the worker is asked to stop before it has started")
        {
            worker.request_shutdown();
            worker.start();
            worker.join();

            THEN("every thread ends, and the work is kept for replay")
            {
                REQUIRE(attempts.load() == 0U);
                REQUIRE(worker.summary().pending == 2U);
            }
        }
    }
}

// F-20: a peer that answers just inside the deadline used to count as healthy, so it could hold a thread for a whole
// attempt every time.
SCENARIO("A slow success grows the destination's backoff", "[f20][federation][dispatch-worker]")
{
    GIVEN("a peer that answers 200, on a clock the test controls")
    {
        auto opened = merovingian::database::open_persistent_store();
        REQUIRE(opened.ok);
        auto& store = opened.store;
        auto certificate = merovingian::tests::tls_mock::write_test_tls_certificate("localhost");
        auto tls_context = merovingian::homeserver::make_tls_server_context(certificate.certificate_file,
                                                                            certificate.private_key_file);
        REQUIRE(tls_context.ok());
        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        auto const port = acceptor.bound_port();
        REQUIRE(port > 0U);
        auto const answer = merovingian::tests::tls_mock::json_http_response("200 OK", R"({"pdus":{}})");
        auto server_thread = std::thread{[&]() {
            merovingian::tests::tls_mock::run_one_shot_tls_server(acceptor, *tls_context.context, answer);
        }};
        auto const join_server = merovingian::tests::tls_mock::ScopedThreadJoin{server_thread};
        std::ignore = join_server;

        auto client = merovingian::http::OutboundClient{};
        auto fake_now = std::atomic<std::uint64_t>{1000U};
        auto attempt_takes_ms = std::atomic<std::uint64_t>{0U};
        auto discoveries = std::atomic<std::size_t>{0U};
        auto resolver = merovingian::federation::DispatchResolver{
            [&, port](std::string_view server_name) -> std::optional<merovingian::federation::ServerDiscoveryResult> {
                ++discoveries;
                fake_now.fetch_add(attempt_takes_ms.load());
                auto discovery = merovingian::federation::ServerDiscoveryResult{};
                discovery.server_name = std::string{server_name};
                discovery.resolved_host = "localhost";
                discovery.tls_server_name = "localhost";
                discovery.resolved_port = port;
                discovery.pinned_addresses = {"127.0.0.1"};
                discovery.discovery_allowed = true;
                return discovery;
            }};
        auto now_ms = merovingian::federation::DispatchClock{[&fake_now] {
            return fake_now.load();
        }};
        auto config = worker_config();
        config.trusted_ca_pem = certificate.certificate_pem;
        auto const slow = config.slow_attempt_ms + 1U;
        auto worker = merovingian::federation::DispatchWorker{std::move(config), client, std::move(resolver),
                                                              std::move(now_ms), {},     &store};
        REQUIRE(worker.enqueue(transaction_named("first", healthy_peer)));

        WHEN("it answers within the limit")
        {
            REQUIRE(worker.run_once());

            THEN("the destination stays healthy")
            {
                REQUIRE(worker.summary().delivered == 1U);
                auto const destination = stored_destination(store, healthy_peer);
                REQUIRE(destination.consecutive_failures == 0U);
                REQUIRE(destination.retry_after_ts == 0U);
            }
        }

        WHEN("it answers only after the limit")
        {
            attempt_takes_ms.store(slow);
            REQUIRE(worker.run_once());

            THEN("the transaction was delivered, and the destination backs off as if it had failed")
            {
                REQUIRE(worker.summary().delivered == 1U);
                auto const destination = stored_destination(store, healthy_peer);
                REQUIRE(destination.consecutive_failures == 1U);
                REQUIRE(destination.retry_after_ts > fake_now.load());
            }

            AND_WHEN("another transaction for it is due during the backoff")
            {
                REQUIRE(worker.enqueue(transaction_named("second", healthy_peer)));
                auto const discoveries_before = discoveries.load();
                REQUIRE(worker.run_once());

                THEN("it takes no thread, not even for discovery, and is kept")
                {
                    REQUIRE(discoveries.load() == discoveries_before);
                    REQUIRE(worker.summary().delivered == 1U);
                    REQUIRE(worker.summary().pending == 1U);
                }
            }
        }

        WHEN("it was already backing off and answers only after the limit again")
        {
            REQUIRE(merovingian::database::store_federation_destination(
                store, {std::string{healthy_peer}, "backoff", 0U, 0U, 3U}));
            std::ignore = worker.replay_pending();
            attempt_takes_ms.store(slow);
            REQUIRE(worker.run_once());

            THEN("the backoff grows")
            {
                REQUIRE(stored_destination(store, healthy_peer).consecutive_failures == 4U);
            }
        }
    }
}
