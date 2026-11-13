// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
// Run-3 finding C36 (ADR-0652): an inbound m.receipt EDU is committed in one transaction, and its receipts are
// found and stored through the receipt indexes, so the work under runtime.mutex is bounded by the EDU and not by the
// receipt table. Cost is shown with the store's counters, never time.
//
// Spec: server-server-api.md, "Receipts": the m.receipt EDU carries "data" with "ts" and optional "thread_id" and an
// "event_ids" list per user.

#include "../support/E2eeCapsSupport.hpp"
#include "merovingian/database/PersistentReceipt.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/federation/EduDispositionResult.hpp"
#include "merovingian/federation/EduDispositionStatus.hpp"
#include "merovingian/federation/EduType.hpp"
#include "merovingian/federation/InboundEduEnvelope.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/LocalHttpRouter.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <string>
#include <string_view>
#include <utility>

namespace
{

namespace db = merovingian::database;

[[nodiscard]] auto deliver(merovingian::homeserver::ClientServerRuntime& runtime, std::string content)
    -> merovingian::federation::EduDispositionResult
{
    auto envelope = merovingian::federation::InboundEduEnvelope{};
    envelope.type = merovingian::federation::EduType::receipt;
    envelope.edu_type = "m.receipt";
    envelope.origin = "remote.example.org";
    envelope.content_json = std::move(content);
    merovingian::homeserver::wire_federation_callbacks(runtime.homeserver);
    REQUIRE(runtime.homeserver.federation.edu_sink != nullptr);
    return runtime.homeserver.federation.edu_sink(envelope);
}

auto join_remote_users(merovingian::homeserver::ClientServerRuntime& runtime, std::string_view room_id,
                       std::size_t users) -> void
{
    auto& store = runtime.homeserver.database.persistent_store;
    store.memberships.push_back({std::string{room_id}, "@alice:example.org", "join", 1U});
    for (auto index = std::size_t{0U}; index < users; ++index)
    {
        store.memberships.push_back(
            {std::string{room_id}, "@u" + std::to_string(index) + ":remote.example.org", "join", 1U});
    }
    db::rebuild_membership_index(store);
    db::rebuild_key_indexes(store);
}

[[nodiscard]] auto receipts_for_users(std::string_view room_id, std::size_t users) -> std::string
{
    auto body = "{\"" + std::string{room_id} + R"(":{"m.read":{)";
    for (auto index = std::size_t{0U}; index < users; ++index)
    {
        body += (index == 0U ? "" : ",") + std::string{"\"@u"} + std::to_string(index) +
                R"(:remote.example.org":{"data":{"ts":1},"event_ids":["$ev1"]})";
    }
    return body + "}}}";
}

} // namespace

SCENARIO("a receipt EDU is committed in one transaction whatever the receipt table holds",
         "[receipts][c36][federation]")
{
    GIVEN("a room with 100 users of the sending server, and a table already holding 3000 other receipts")
    {
        auto started = merovingian::homeserver::start_client_server(merovingian::tests::caps_config(100U, 100U, 100U));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto& store = runtime.homeserver.database.persistent_store;
        join_remote_users(runtime, "!busy:example.org", 100U);
        for (auto index = std::size_t{0U}; index < 3000U; ++index)
        {
            auto receipt = db::PersistentReceipt{};
            receipt.room_id = "!far" + std::to_string(index % 30U) + ":example.org";
            receipt.user_id = "@far" + std::to_string(index) + ":other.example";
            receipt.event_id = "$far";
            REQUIRE(db::store_receipt(store, std::move(receipt)));
        }

        WHEN("an EDU carrying 100 receipts is delivered")
        {
            auto const transactions = db::committed_transaction_count(store);
            auto const examined = store.receipt_rows_examined.value();
            auto const result = deliver(runtime, receipts_for_users("!busy:example.org", 100U));

            THEN("all 100 are stored by one commit, and few receipt rows were read")
            {
                REQUIRE(result.status == merovingian::federation::EduDispositionStatus::accepted);
                REQUIRE(db::receipts_in_room(store, "!busy:example.org").size() == 100U);
                REQUIRE(db::committed_transaction_count(store) - transactions == 1U);
                REQUIRE(store.receipt_rows_examined.value() - examined <= 400U);
            }
        }

        WHEN("the same EDU is delivered again")
        {
            REQUIRE(deliver(runtime, receipts_for_users("!busy:example.org", 100U)).status ==
                    merovingian::federation::EduDispositionStatus::accepted);
            auto const transactions = db::committed_transaction_count(store);
            REQUIRE(deliver(runtime, receipts_for_users("!busy:example.org", 100U)).status ==
                    merovingian::federation::EduDispositionStatus::accepted);

            THEN("the receipts are replaced, not added, in one commit")
            {
                REQUIRE(db::receipts_in_room(store, "!busy:example.org").size() == 100U);
                REQUIRE(db::committed_transaction_count(store) - transactions == 1U);
            }
        }
    }
}
