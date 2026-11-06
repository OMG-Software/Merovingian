// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
// P5 (ADR-0441). An event used to commit one federation_transactions row per remote server, each followed by a
// linear search of the queue, and SQLite syncs every commit. The destinations of one event are now enqueued as a
// batch committed in one transaction: durable before anything can be sent, all or none, and still bounded by the
// queue depth and each destination's share of it (ADR-0177).

#include "federation_signing_test_support.hpp"
#include "merovingian/database/PersistentFederationTransaction.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/PersistentStoreOpenResult.hpp"
#include "merovingian/federation/dispatch_worker.hpp"
#include "merovingian/federation/outbound_transaction.hpp"
#include "merovingian/http/outbound_client.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace
{

[[nodiscard]] auto batch_transaction(std::string id, std::string destination)
    -> merovingian::federation::OutboundTransaction
{
    auto transaction = merovingian::federation::OutboundTransaction{};
    transaction.transaction_id = std::move(id);
    transaction.destination = std::move(destination);
    transaction.method = "PUT";
    transaction.target = "/_matrix/federation/v1/send/x";
    transaction.origin = "origin.example.org";
    transaction.body = R"({"pdus":[]})";
    return transaction;
}

[[nodiscard]] auto batch_config() -> merovingian::federation::DispatchWorkerConfig
{
    auto config = merovingian::federation::DispatchWorkerConfig{};
    config.origin = "origin.example.org";
    config.key_id = "ed25519:auto";
    config.secret_key = merovingian::federation::test::secret_key_buffer(
        merovingian::federation::test::keypair_from_seed("deterministic-test-token"));
    config.max_queue_depth = 16U;
    config.idle_poll = std::chrono::milliseconds{5};
    return config;
}

[[nodiscard]] auto destinations(std::size_t count) -> std::vector<merovingian::federation::OutboundTransaction>
{
    auto batch = std::vector<merovingian::federation::OutboundTransaction>{};
    for (auto index = std::size_t{0U}; index < count; ++index)
    {
        batch.push_back(batch_transaction("txn-" + std::to_string(index), "server" + std::to_string(index) + ".org"));
    }
    return batch;
}

} // namespace

SCENARIO("a batch of destinations is queued in one durable commit", "[federation][dispatch-worker][batch][p5]")
{
    GIVEN("a worker with a persistent store and an idle queue")
    {
        // A real persistent store, so the rows and committed transactions the batch produces can be
        // counted directly.
        auto opened = merovingian::database::open_persistent_store();
        REQUIRE(opened.ok);
        auto client = merovingian::http::OutboundClient{};
        // The resolver always finds nothing, so no transaction can be delivered while the test runs: what is
        // counted is only what was queued.
        auto worker = merovingian::federation::DispatchWorker{
            batch_config(),
            client,
            merovingian::federation::DispatchResolver{[](std::string_view) {
                return std::optional<merovingian::federation::ServerDiscoveryResult>{};
            }},
            {},
            {},
            &opened.store};

        WHEN("an event is queued to eight servers at once")
        {
            // The commit count is read before and after, because one shared commit, not eight, is the point of a
            // batch.
            auto const commits_before = merovingian::database::committed_transaction_count(opened.store);
            auto const accepted = worker.enqueue_batch(destinations(8U));

            THEN("every destination is accepted and the rows share one committed transaction")
            {
                REQUIRE(accepted.size() == 8U);
                CHECK(std::ranges::all_of(accepted, [](bool ok) {
                    return ok;
                }));
                CHECK(merovingian::database::committed_transaction_count(opened.store) - commits_before == 1U);
            }
            THEN("each row is on disk before anything could be sent, and the queue counts them")
            {
                CHECK(opened.store.federation_transactions.size() == 8U);
                CHECK(worker.summary().enqueued == 8U);
                CHECK(worker.summary().pending == 8U);
            }
        }

        WHEN("the commit of a batch fails")
        {
            // The next persist fails. A batch has one commit, so that single failure must undo every row of it.
            merovingian::database::force_next_persist_failures(opened.store, 1U);
            auto const accepted = worker.enqueue_batch(destinations(3U));

            THEN("nothing is half queued: no destination is accepted, stored or pending")
            {
                REQUIRE(accepted.size() == 3U);
                CHECK_FALSE(std::ranges::any_of(accepted, [](bool ok) {
                    return ok;
                }));
                CHECK(opened.store.federation_transactions.empty());
                CHECK(worker.summary().pending == 0U);
                CHECK(worker.summary().enqueued == 0U);
            }
        }

        WHEN("a batch holds a malformed transaction beside good ones")
        {
            auto batch = destinations(3U);
            // An empty body makes the middle transaction invalid, while its neighbours stay valid.
            batch[1].body.clear();
            auto const accepted = worker.enqueue_batch(std::move(batch));

            THEN("only the malformed one is refused")
            {
                REQUIRE(accepted.size() == 3U);
                CHECK(accepted[0]);
                CHECK_FALSE(accepted[1]);
                CHECK(accepted[2]);
                CHECK(opened.store.federation_transactions.size() == 2U);
            }
        }

        WHEN("a batch is larger than the room left in the queue")
        {
            // The queue depth is 16 in batch_config, so four of the twenty cannot fit.
            auto const accepted = worker.enqueue_batch(destinations(20U));

            THEN("the queue depth bound still holds, counting the batch's own earlier members")
            {
                auto const taken = static_cast<std::size_t>(std::ranges::count(accepted, true));
                CHECK(taken == 16U);
                CHECK(opened.store.federation_transactions.size() == 16U);
                CHECK(worker.summary().rejected == 4U);
            }
        }
    }

    GIVEN("a worker whose destinations may hold one queued transaction each")
    {
        auto opened = merovingian::database::open_persistent_store();
        REQUIRE(opened.ok);
        auto config = batch_config();
        // One queued transaction per destination, so a second to the same server in one batch must be refused.
        config.max_pending_per_destination = 1U;
        auto client = merovingian::http::OutboundClient{};
        auto worker = merovingian::federation::DispatchWorker{
            std::move(config),
            client,
            merovingian::federation::DispatchResolver{[](std::string_view) {
                return std::optional<merovingian::federation::ServerDiscoveryResult>{};
            }},
            {},
            {},
            &opened.store};

        WHEN("a batch names the same destination twice")
        {
            auto batch = std::vector<merovingian::federation::OutboundTransaction>{};
            // Both transactions in the batch go to one destination. The share has to count the batch's own
            // earlier members, since the second is judged in the same call as the first.
            batch.push_back(batch_transaction("a", "same.org"));
            batch.push_back(batch_transaction("b", "same.org"));
            auto const accepted = worker.enqueue_batch(std::move(batch));

            THEN("the destination's share is enforced inside the batch")
            {
                REQUIRE(accepted.size() == 2U);
                CHECK(accepted[0]);
                CHECK_FALSE(accepted[1]);
                CHECK(opened.store.federation_transactions.size() == 1U);
            }
        }
    }
}

SCENARIO("a stored federation transaction is found by its ID, replaced in place and deleted",
         "[database][federation][batch][p5]")
{
    GIVEN("a store holding three queued transactions")
    {
        auto opened = merovingian::database::open_persistent_store();
        REQUIRE(opened.ok);
        auto& store = opened.store;
        auto const row = [](std::string id, std::string destination, std::uint32_t retries) {
            return merovingian::database::PersistentFederationTransaction{
                std::move(id), std::move(destination), "PUT", "/x", "origin.example.org", "1", "{}", retries, 0U};
        };
        REQUIRE(merovingian::database::store_federation_transaction(store, row("a", "a.org", 0U)));
        REQUIRE(merovingian::database::store_federation_transaction(store, row("b", "b.org", 0U)));
        REQUIRE(merovingian::database::store_federation_transaction(store, row("c", "c.org", 0U)));

        WHEN("a retry count is updated and the first row is deleted")
        {
            REQUIRE(merovingian::database::store_federation_transaction(store, row("b", "b.org", 4U)));
            REQUIRE(merovingian::database::delete_federation_transaction(store, "a"));

            THEN("the update replaced the row, the delete removed only its row, and later lookups still find theirs")
            {
                REQUIRE(store.federation_transactions.size() == 2U);
                REQUIRE(merovingian::database::store_federation_transaction(store, row("c", "c.org", 7U)));
                REQUIRE(store.federation_transactions.size() == 2U);
                auto retries = std::vector<std::uint32_t>{};
                for (auto const& stored : store.federation_transactions)
                {
                    retries.push_back(stored.retry_count);
                }
                CHECK(std::ranges::count(retries, 4U) == 1);
                CHECK(std::ranges::count(retries, 7U) == 1);
            }
        }

        WHEN("a batch holds a malformed row")
        {
            auto bad = row("d", "d.org", 0U);
            bad.body.clear();
            auto batch = std::vector<merovingian::database::PersistentFederationTransaction>{};
            batch.push_back(row("e", "e.org", 0U));
            batch.push_back(std::move(bad));

            THEN("it is refused whole and nothing is added")
            {
                CHECK_FALSE(merovingian::database::store_federation_transactions(store, std::move(batch)));
                CHECK(store.federation_transactions.size() == 3U);
            }
        }
    }
}
