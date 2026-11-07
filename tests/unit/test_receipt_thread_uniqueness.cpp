// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Analysis finding S4: ReceiptContentBuilder::build() files a receipt under (event, type, user), so one user can
// appear under two events. That is spec-valid only for receipts of different threads, and the store holds exactly
// one receipt per (room, user, receipt type, thread_id).
//
// Spec: Matrix Client-Server API v1.19, "Receipts": each user_id, receipt_type and categorisation (unthreaded, or
// thread_id) tuple is associated with only a single event_id.
// URL:  ../../docs/matrix-v1.19-spec/client-server-api.md#receipts

#include "../support/json_test_support.hpp"
#include "merovingian/canonicaljson/ObjectMember.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/database/PersistentReceipt.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/PersistentStoreOpenResult.hpp"
#include "merovingian/sync/ReceiptContentBuilder.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <variant>

using merovingian::database::PersistentReceipt;

namespace
{

[[nodiscard]] auto receipt(std::string event_id, std::string thread_id, std::uint64_t ts) -> PersistentReceipt
{
    auto result = PersistentReceipt{};
    result.room_id = "!room:example.org";
    result.user_id = "@alice:example.org";
    result.event_id = std::move(event_id);
    result.thread_id = std::move(thread_id);
    result.ts = ts;
    return result;
}

[[nodiscard]] auto events_naming_user(merovingian::canonicaljson::Object const& content) -> std::size_t
{
    auto count = std::size_t{0U};
    for (auto const& member : content)
    {
        auto const* types = std::get_if<merovingian::canonicaljson::Object>(&member.value->storage());
        auto const* read = types == nullptr ? nullptr : merovingian::tests::object_member_as_object(*types, "m.read");
        if (read != nullptr && merovingian::tests::object_member(*read, "@alice:example.org") != nullptr)
        {
            ++count;
        }
    }
    return count;
}

} // namespace

SCENARIO("S4 a user is under two events of a receipt only for different threads", "[receipts][s4][threads]")
{
    GIVEN("a store that holds a user's receipts")
    {
        auto opened = merovingian::database::open_persistent_store();
        REQUIRE(opened.ok);
        auto& store = opened.store;

        WHEN("the user sets receipts for two events in two different threads")
        {
            REQUIRE(merovingian::database::store_receipt(store, receipt("$a", "main", 1U), std::nullopt));
            REQUIRE(merovingian::database::store_receipt(store, receipt("$b", "$root", 2U), std::nullopt));
            auto builder = merovingian::sync::ReceiptContentBuilder{};
            for (auto const& stored : store.receipts)
            {
                builder.add(stored);
            }

            THEN("the user appears under both events")
            {
                REQUIRE(store.receipts.size() == 2U);
                REQUIRE(events_naming_user(builder.build()) == 2U);
            }
        }

        WHEN("the user sets receipts for two events in the same thread")
        {
            REQUIRE(merovingian::database::store_receipt(store, receipt("$a", "main", 1U), std::nullopt));
            REQUIRE(merovingian::database::store_receipt(store, receipt("$b", "main", 2U), std::nullopt));
            auto builder = merovingian::sync::ReceiptContentBuilder{};
            for (auto const& stored : store.receipts)
            {
                builder.add(stored);
            }

            THEN("the store holds only the newest, and the user appears under one event")
            {
                REQUIRE(store.receipts.size() == 1U);
                REQUIRE(store.receipts.front().event_id == "$b");
                REQUIRE(events_naming_user(builder.build()) == 1U);
            }
        }
    }
}
