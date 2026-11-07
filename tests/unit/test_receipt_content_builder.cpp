// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// Unit tests for sync::ReceiptContentBuilder::add, empty and build.
//
// Spec (client-server-api.md, "Receipts"): an m.receipt event's content is
// {event_id: {receipt_type: {user_id: {"ts": N, "thread_id": T}}}}; `thread_id` is present only on a
// threaded receipt.

#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/database/PersistentReceipt.hpp"
#include "merovingian/sync/ReceiptContentBuilder.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <string>
#include <utility>

namespace
{

[[nodiscard]] auto receipt(std::string event_id, std::string type, std::string user, std::uint64_t ts,
                           std::uint64_t stream_id, std::string thread_id = {})
    -> merovingian::database::PersistentReceipt
{
    auto result = merovingian::database::PersistentReceipt{};
    result.room_id = "!room:example.org";
    result.event_id = std::move(event_id);
    result.receipt_type = std::move(type);
    result.user_id = std::move(user);
    result.ts = ts;
    result.stream_id = stream_id;
    result.thread_id = std::move(thread_id);
    return result;
}

[[nodiscard]] auto rendered(merovingian::sync::ReceiptContentBuilder const& builder) -> std::string
{
    return merovingian::canonicaljson::serialize_canonical(merovingian::canonicaljson::Value{builder.build()}).output;
}

} // namespace

SCENARIO("Receipt content is built from stored receipts", "[sync][receipts][unit]")
{
    GIVEN("an empty builder")
    {
        auto builder = merovingian::sync::ReceiptContentBuilder{};

        WHEN("nothing has been added")
        {
            THEN("it is empty and renders an empty object")
            {
                REQUIRE(builder.empty());
                REQUIRE(rendered(builder) == "{}");
            }
        }

        WHEN("an unthreaded receipt is added")
        {
            builder.add(receipt("$e1", "m.read", "@a:x", 100U, 1U));

            THEN("the content nests event, type and user, with a ts and no thread_id")
            {
                REQUIRE_FALSE(builder.empty());
                REQUIRE(rendered(builder) == R"({"$e1":{"m.read":{"@a:x":{"ts":100}}}})");
            }
        }

        WHEN("a threaded receipt is added")
        {
            builder.add(receipt("$e1", "m.read", "@a:x", 100U, 1U, "$root"));

            THEN("it carries its thread_id")
            {
                REQUIRE(rendered(builder) == R"({"$e1":{"m.read":{"@a:x":{"thread_id":"$root","ts":100}}}})");
            }
        }

        WHEN("receipts of several types, users and events are added")
        {
            builder.add(receipt("$e1", "m.read", "@a:x", 1U, 1U));
            builder.add(receipt("$e1", "m.read", "@b:x", 2U, 2U));
            builder.add(receipt("$e1", "m.read.private", "@a:x", 3U, 3U));
            builder.add(receipt("$e2", "m.read", "@a:x", 4U, 4U));

            THEN("each lands under its own event, type and user")
            {
                REQUIRE(rendered(builder) ==
                        R"({"$e1":{"m.read":{"@a:x":{"ts":1},"@b:x":{"ts":2}},"m.read.private":{"@a:x":{"ts":3}}},)"
                        R"("$e2":{"m.read":{"@a:x":{"ts":4}}}})");
            }
        }
    }

    GIVEN("a builder holding one receipt from a user")
    {
        auto builder = merovingian::sync::ReceiptContentBuilder{};
        builder.add(receipt("$e1", "m.read", "@a:x", 100U, 5U));

        WHEN("an older receipt for the same user, event and type arrives later")
        {
            builder.add(receipt("$e1", "m.read", "@a:x", 50U, 4U));

            THEN("the newer one (higher stream_id) is kept")
            {
                REQUIRE(rendered(builder) == R"({"$e1":{"m.read":{"@a:x":{"ts":100}}}})");
            }
        }

        WHEN("a newer receipt for the same user, event and type arrives")
        {
            builder.add(receipt("$e1", "m.read", "@a:x", 200U, 6U));

            THEN("it replaces the older one")
            {
                REQUIRE(rendered(builder) == R"({"$e1":{"m.read":{"@a:x":{"ts":200}}}})");
            }
        }
    }
}
