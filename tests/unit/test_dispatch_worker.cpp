// SPDX-License-Identifier: GPL-3.0-or-later

#include "federation_signing_test_support.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/federation/dispatch_worker.hpp"
#include "merovingian/federation/outbound_transaction.hpp"
#include "merovingian/federation/server_discovery.hpp"
#include "merovingian/http/outbound_client.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <thread>

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
            REQUIRE(worker.run_once());

            THEN("the circuit-open transaction stays pending for retry instead of being discarded")
            {
                auto const summary = worker.summary();
                REQUIRE(summary.failed >= 4U);
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

        WHEN("it runs for 200 ms")
        {
            worker.start();
            std::this_thread::sleep_for(std::chrono::milliseconds{200});
            worker.request_shutdown();
            worker.join();

            THEN("it looked at the clock about once per idle poll, not millions of times")
            {
                CAPTURE(clock_reads->load());
                REQUIRE(clock_reads->load() < 1000U);
            }
        }
    }
}
