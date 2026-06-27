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
    config.secret_key = merovingian::federation::test::keypair_from_seed("deterministic-test-token").secret_key;
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

            THEN("the worker exits cleanly and the summary records the dropped transaction")
            {
                auto const summary = worker.summary();
                REQUIRE(summary.enqueued >= 1U);
                REQUIRE(summary.dropped >= 1U);
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
