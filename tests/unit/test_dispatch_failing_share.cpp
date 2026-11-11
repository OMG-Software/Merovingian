// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
// Release-gate audit, resource-exhaustion.dispatch-worker.sixteen-dead-destinations-fill-shared-outbound-queue
// (ADR-0621). A destination's share (ADR-0177) bounds one peer, not the number of peers, so sixteen peers that stop
// answering held the whole queue for weeks and every other peer's transactions were refused. Destinations that are
// failing now hold at most half of the queue between them, and their transactions leave past an age.

#include "FederationSigningTestSupport.hpp"
#include "merovingian/database/PersistentFederationDestination.hpp"
#include "merovingian/database/PersistentFederationTransaction.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/PersistentStoreOpenResult.hpp"
#include "merovingian/federation/DispatchWorker.hpp"
#include "merovingian/federation/DispatchWorkerConfig.hpp"
#include "merovingian/federation/OutboundTransaction.hpp"
#include "merovingian/http/OutboundClient.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>

namespace
{

namespace federation = merovingian::federation;

constexpr auto start_ms = std::uint64_t{1'000'000'000U};
constexpr auto day_ms = std::uint64_t{24U * 60U * 60U * 1000U};
constexpr auto live_peer = std::string_view{"live.example.org"};

[[nodiscard]] auto dead_peer(std::size_t index) -> std::string
{
    return "dead" + std::to_string(index) + ".example.org";
}

[[nodiscard]] auto transaction_for(std::string destination, std::size_t serial) -> federation::OutboundTransaction
{
    auto transaction = federation::OutboundTransaction{};
    transaction.transaction_id = destination + "-" + std::to_string(serial);
    transaction.target = "/_matrix/federation/v1/send/" + transaction.transaction_id;
    transaction.destination = std::move(destination);
    transaction.method = "PUT";
    transaction.origin = "origin.example.org";
    transaction.body = R"({"pdus":[]})";
    return transaction;
}

[[nodiscard]] auto config_with_depth(std::size_t depth) -> federation::DispatchWorkerConfig
{
    auto config = federation::DispatchWorkerConfig{};
    config.origin = "origin.example.org";
    config.key_id = "ed25519:auto";
    config.secret_key = federation::test::secret_key_buffer(federation::test::keypair_from_seed("failing-share-seed"));
    config.max_queue_depth = depth;
    config.max_retries = 1000U;
    return config;
}

// Queue 16 with a destination share of 8, so the failing share is 8: left to itself a destination's share is at least
// 16, and the failing share is never below it.
[[nodiscard]] auto config_with_failing_share_of_eight() -> federation::DispatchWorkerConfig
{
    auto config = config_with_depth(16U);
    config.max_pending_per_destination = 8U;
    return config;
}

// Every peer fails discovery, so nothing reaches the network. The attempts made on each are counted.
struct CountingPeers final
{
    std::map<std::string, std::size_t, std::less<>> attempts{};

    [[nodiscard]] auto resolver() -> federation::DispatchResolver
    {
        return [this](std::string_view server_name) -> std::optional<federation::ServerDiscoveryResult> {
            ++attempts[std::string{server_name}];
            return std::nullopt;
        };
    }

    [[nodiscard]] auto of(std::string_view server_name) const -> std::size_t
    {
        auto const found = attempts.find(server_name);
        return found == attempts.end() ? 0U : found->second;
    }
};

// Queues `each` transactions for `peers` dead destinations and makes each fail once.
auto fill_and_fail(federation::DispatchWorker& worker, std::size_t peers, std::size_t each) -> void
{
    for (auto peer = std::size_t{0U}; peer < peers; ++peer)
    {
        for (auto serial = std::size_t{0U}; serial < each; ++serial)
        {
            REQUIRE(worker.enqueue(transaction_for(dead_peer(peer), serial)));
        }
    }
    for (auto peer = std::size_t{0U}; peer < peers; ++peer)
    {
        REQUIRE(worker.run_once());
    }
}

} // namespace

SCENARIO("Sixteen dead destinations leave room in the queue for a live one",
         "[federation][dispatch-worker][dispatch-failing-share][security]")
{
    GIVEN("the production queue with sixteen destinations each at its share, and every one failing")
    {
        auto now = start_ms;
        auto peers = CountingPeers{};
        auto client = merovingian::http::OutboundClient{};
        auto worker = federation::DispatchWorker{config_with_depth(4096U),
                                                 client,
                                                 peers.resolver(),
                                                 [&now] {
                                                     return now;
                                                 },
                                                 {}};
        fill_and_fail(worker, 16U, 256U);

        WHEN("the queue is looked at after each has failed once")
        {
            auto const summary = worker.summary();

            THEN("the failing destinations hold exactly half of it, an equal share each")
            {
                REQUIRE(summary.enqueued == 4096U);
                REQUIRE(summary.dropped == 2048U);
                REQUIRE(summary.pending == 2048U);
            }
        }

        WHEN("a live destination is offered a transaction and a dead one another")
        {
            auto const live = worker.enqueue(transaction_for(std::string{live_peer}, 0U));
            auto const dead = worker.enqueue(transaction_for(dead_peer(0U), 999U));

            THEN("the live one is admitted and attempted, and the dead one is refused and counted")
            {
                REQUIRE(live);
                REQUIRE_FALSE(dead);
                REQUIRE(worker.summary().rejected == 1U);
                REQUIRE(worker.run_once());
                REQUIRE(peers.of(live_peer) == 1U);
            }
        }
    }

    GIVEN("a queue of 64 and three dead destinations that together hold less than half of it")
    {
        auto now = start_ms;
        auto peers = CountingPeers{};
        auto client = merovingian::http::OutboundClient{};
        auto worker = federation::DispatchWorker{config_with_depth(64U),
                                                 client,
                                                 peers.resolver(),
                                                 [&now] {
                                                     return now;
                                                 },
                                                 {}};
        fill_and_fail(worker, 3U, 10U);

        WHEN("each has failed once")
        {
            auto const before = worker.summary();
            // One below the failing share of 32, then at it.
            auto const up_to_share = worker.enqueue(transaction_for(dead_peer(0U), 100U)) &&
                                     worker.enqueue(transaction_for(dead_peer(1U), 100U));
            auto const past_share = worker.enqueue(transaction_for(dead_peer(2U), 100U));

            THEN("nothing is dropped, and they are admitted up to the failing share and no further")
            {
                REQUIRE(before.dropped == 0U);
                REQUIRE(before.pending == 30U);
                REQUIRE(up_to_share);
                REQUIRE_FALSE(past_share);
                REQUIRE(worker.summary().pending == 32U);
            }
        }
    }

    GIVEN("the failing share spent, and a failing destination whose backoff has ended")
    {
        auto now = start_ms;
        auto peers = CountingPeers{};
        auto client = merovingian::http::OutboundClient{};
        auto worker = federation::DispatchWorker{config_with_failing_share_of_eight(),
                                                 client,
                                                 peers.resolver(),
                                                 [&now] {
                                                     return now;
                                                 },
                                                 {}};
        // Two destinations, so that neither is at its own share of eight.
        fill_and_fail(worker, 2U, 4U);
        REQUIRE_FALSE(worker.enqueue(transaction_for(dead_peer(0U), 100U)));

        WHEN("it is offered a transaction after an hour")
        {
            now = start_ms + 60U * 60U * 1000U;
            auto const admitted = worker.enqueue(transaction_for(dead_peer(0U), 101U));

            THEN("it is admitted, because only a try can show that it has recovered")
            {
                REQUIRE(admitted);
                REQUIRE(worker.summary().pending == 9U);
            }
        }
    }
}

SCENARIO("One failing destination keeps its own share on a queue too small to divide",
         "[federation][dispatch-worker][dispatch-failing-share]")
{
    GIVEN("a queue of four, all of it held by one destination")
    {
        auto now = start_ms;
        auto peers = CountingPeers{};
        auto client = merovingian::http::OutboundClient{};
        auto worker = federation::DispatchWorker{config_with_depth(4U),
                                                 client,
                                                 peers.resolver(),
                                                 [&now] {
                                                     return now;
                                                 },
                                                 {}};

        WHEN("that destination fails")
        {
            fill_and_fail(worker, 1U, 4U);

            THEN("it loses nothing, because the failing share bounds many destinations and not one")
            {
                REQUIRE(worker.summary().dropped == 0U);
                REQUIRE(worker.summary().pending == 4U);
            }
        }
    }
}

SCENARIO("A failing destination's transactions leave past an age and are retried until then",
         "[federation][dispatch-worker][dispatch-failing-share][security]")
{
    GIVEN("a failing destination with three queued transactions and a live one that has not been tried")
    {
        auto now = start_ms;
        auto peers = CountingPeers{};
        auto client = merovingian::http::OutboundClient{};
        auto config = config_with_depth(64U);
        auto worker = federation::DispatchWorker{std::move(config),
                                                 client,
                                                 peers.resolver(),
                                                 [&now] {
                                                     return now;
                                                 },
                                                 {}};
        fill_and_fail(worker, 1U, 3U);

        WHEN("just under a day has passed, driving the worker as time goes by")
        {
            for (auto step = std::uint64_t{0U}; step < 287U; ++step)
            {
                now += 5U * 60U * 1000U;
                std::ignore = worker.run_once();
            }
            now = start_ms + day_ms;
            std::ignore = worker.run_once();

            THEN("nothing has been dropped, and the destination's oldest kept being retried")
            {
                REQUIRE(worker.summary().dropped == 0U);
                REQUIRE(worker.summary().pending == 3U);
                REQUIRE(peers.of(dead_peer(0U)) > 200U);
            }
        }

        WHEN("more than a day has passed")
        {
            now = start_ms + day_ms + 60U * 1000U + 1U;
            std::ignore = worker.run_once();

            THEN("all three are gone")
            {
                REQUIRE(worker.summary().dropped == 3U);
                REQUIRE(worker.summary().pending == 0U);
            }
        }
    }

    GIVEN("a transaction for a destination that has never failed, behind a failing one that is not due")
    {
        auto now = start_ms;
        auto peers = CountingPeers{};
        auto client = merovingian::http::OutboundClient{};
        auto worker = federation::DispatchWorker{config_with_depth(64U),
                                                 client,
                                                 peers.resolver(),
                                                 [&now] {
                                                     return now;
                                                 },
                                                 {}};
        auto transaction = transaction_for(std::string{live_peer}, 0U);
        // Not due for two days, so the worker does not try it: the destination never fails.
        transaction.next_retry_ts = start_ms + 2U * day_ms;
        REQUIRE(worker.enqueue(std::move(transaction)));

        WHEN("more than a day has passed")
        {
            now = start_ms + day_ms + 60U * 1000U + 1U;
            std::ignore = worker.run_once();

            THEN("it is kept, because only a failing destination's transactions age out")
            {
                REQUIRE(worker.summary().dropped == 0U);
                REQUIRE(worker.summary().pending == 1U);
            }
        }
    }
}

SCENARIO("A restart does not bring the dead destinations' transactions back over the failing share",
         "[federation][dispatch-worker][dispatch-failing-share][persistence][security]")
{
    GIVEN("durable rows for two failing destinations past the failing share, and one for a live destination")
    {
        auto opened = merovingian::database::open_persistent_store();
        REQUIRE(opened.ok);
        auto& store = opened.store;
        auto const row_ts = std::to_string(start_ms);
        for (auto peer = std::size_t{0U}; peer < 2U; ++peer)
        {
            REQUIRE(merovingian::database::store_federation_destination(
                store, {dead_peer(peer), "backoff", start_ms + 1000U, 0U, 5U}));
            for (auto serial = std::size_t{0U}; serial < 10U; ++serial)
            {
                auto const id = dead_peer(peer) + "-" + std::to_string(serial);
                REQUIRE(merovingian::database::store_federation_transaction(
                    store, {id, dead_peer(peer), "PUT", "/_matrix/federation/v1/send/" + id, "origin.example.org",
                            row_ts, R"({"pdus":[]})", 0U, start_ms + 1000U}));
            }
        }
        REQUIRE(merovingian::database::store_federation_transaction(
            store, {"live-0", std::string{live_peer}, "PUT", "/_matrix/federation/v1/send/live-0", "origin.example.org",
                    row_ts, R"({"pdus":[]})", 0U, 0U}));

        auto now = start_ms;
        auto peers = CountingPeers{};
        auto client = merovingian::http::OutboundClient{};
        auto worker = federation::DispatchWorker{config_with_failing_share_of_eight(),
                                                 client,
                                                 peers.resolver(),
                                                 [&now] {
                                                     return now;
                                                 },
                                                 {},
                                                 &store};

        WHEN("the rows are replayed")
        {
            auto const replayed = worker.replay_pending();

            THEN("the failing destinations get the failing share, the live row is queued, and the rest wait")
            {
                REQUIRE(replayed == 9U);
                REQUIRE(worker.summary().pending == 9U);
                REQUIRE(store.federation_transactions.size() == 21U);
            }
        }

        WHEN("the rows are replayed and more than a day passes")
        {
            std::ignore = worker.replay_pending();
            now = start_ms + day_ms + 60U * 1000U + 1U;
            std::ignore = worker.run_once();

            THEN("the failing destinations' rows are gone from the queue, the parked list and the database")
            {
                REQUIRE(worker.summary().dropped == 20U);
                REQUIRE(store.federation_transactions.size() == 1U);
                REQUIRE(store.federation_transactions.front().transaction_id == "live-0");
            }
        }
    }
}
