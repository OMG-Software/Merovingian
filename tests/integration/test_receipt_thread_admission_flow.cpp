// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
// Run-3 finding C23 (ADR-0737): a threaded receipt is accepted only for an event related to its thread, and /sync reads
// receipts through the room indexes, so rows of other rooms and users cost it nothing.
//
// Spec: client-server-api.md, POST /rooms/{roomId}/receipt/{receiptType}/{eventId}: 400 when "The `event_id` is not
// related to the `thread_id`".

#include "../support/E2eeCapsSupport.hpp"
#include "../support/JsonTestSupport.hpp"
#include "merovingian/database/PersistentReceipt.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <string>
#include <string_view>

namespace
{

namespace db = merovingian::database;
namespace hs = merovingian::homeserver;

[[nodiscard]] auto send_event(hs::ClientServerRuntime& runtime, std::string const& token, std::string const& room_id,
                              std::string const& txn, std::string const& relation) -> std::string
{
    auto const sent = hs::handle_client_server_request(
        runtime, {"PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/" + txn, token,
                  R"({"msgtype":"m.text","body":"b")" + relation + "}"});
    REQUIRE(sent.response.status == 200U);
    return merovingian::tests::string_field(sent.response.body, "event_id");
}

[[nodiscard]] auto post_receipt(hs::ClientServerRuntime& runtime, std::string const& token, std::string const& room_id,
                                std::string const& event_id, std::string const& thread_id) -> hs::LocalHttpResponse
{
    return hs::handle_client_server_request(
               runtime, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/receipt/m.read.private/" + event_id, token,
                         thread_id.empty() ? std::string{} : R"({"thread_id":")" + thread_id + R"("})"})
        .response;
}

} // namespace

SCENARIO("a threaded receipt must name an event related to its thread", "[receipts][c23][threads]")
{
    GIVEN("a room with a thread root, a reply in the thread, and two unrelated messages")
    {
        auto started = hs::start_client_server(merovingian::tests::caps_config(100U, 100U, 100U));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = merovingian::tests::register_and_login_alice(runtime);
        auto const created =
            hs::handle_client_server_request(runtime, {"POST", "/_matrix/client/v3/createRoom", token, "{}"});
        REQUIRE(created.response.status == 200U);
        auto const room_id = merovingian::tests::string_field(created.response.body, "room_id");
        auto const root = send_event(runtime, token, room_id, "t0", "");
        auto const reply = send_event(runtime, token, room_id, "t1",
                                      R"(,"m.relates_to":{"rel_type":"m.thread","event_id":")" + root + R"("})");
        auto const other_one = send_event(runtime, token, room_id, "t2", "");
        auto const other_two = send_event(runtime, token, room_id, "t3", "");
        auto& store = runtime.homeserver.database.persistent_store;

        WHEN("receipts are posted for the root and the reply under the thread")
        {
            THEN("both are accepted, and the thread holds the later one")
            {
                REQUIRE(post_receipt(runtime, token, room_id, root, root).status == 200U);
                REQUIRE(post_receipt(runtime, token, room_id, reply, root).status == 200U);
                auto const rows = db::receipts_of_user_in_room(store, room_id, "@alice:example.org");
                REQUIRE(rows.size() == 1U);
                REQUIRE(rows.front()->event_id == reply);
                REQUIRE(rows.front()->thread_id == root);
            }
        }

        WHEN("receipts are posted under main, or unthreaded")
        {
            THEN("they are accepted for any event")
            {
                REQUIRE(post_receipt(runtime, token, room_id, other_one, "main").status == 200U);
                REQUIRE(post_receipt(runtime, token, room_id, other_two, "").status == 200U);
            }
        }

        WHEN("a receipt names an event that is not related to the thread")
        {
            auto const unrelated = post_receipt(runtime, token, room_id, other_one, root);
            auto const other_as_root = post_receipt(runtime, token, room_id, other_one, other_two);
            auto const unknown_event = post_receipt(runtime, token, room_id, "$unknown", root);

            THEN("each is refused with M_INVALID_PARAM and nothing is stored")
            {
                REQUIRE(unrelated.status == 400U);
                REQUIRE(unrelated.body.find("M_INVALID_PARAM") != std::string::npos);
                REQUIRE(other_as_root.status == 400U);
                REQUIRE(other_as_root.body.find("M_INVALID_PARAM") != std::string::npos);
                REQUIRE(unknown_event.status == 400U);
                REQUIRE(db::receipts_of_user_in_room(store, room_id, "@alice:example.org").empty());
            }
        }
    }
}

SCENARIO("/sync reads receipts of its own rooms, not the table", "[receipts][c23][sync]")
{
    GIVEN("a user in one room and a thousand receipts of other users in other rooms")
    {
        auto started = hs::start_client_server(merovingian::tests::caps_config(100U, 100U, 100U));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = merovingian::tests::register_and_login_alice(runtime);
        auto const created =
            hs::handle_client_server_request(runtime, {"POST", "/_matrix/client/v3/createRoom", token, "{}"});
        REQUIRE(created.response.status == 200U);
        auto const room_id = merovingian::tests::string_field(created.response.body, "room_id");
        auto const event_id = send_event(runtime, token, room_id, "t0", "");
        REQUIRE(post_receipt(runtime, token, room_id, event_id, "main").status == 200U);
        auto& store = runtime.homeserver.database.persistent_store;
        for (auto number = std::size_t{0U}; number < 1000U; ++number)
        {
            auto receipt = db::PersistentReceipt{};
            receipt.room_id = "!far" + std::to_string(number % 50U) + ":example.org";
            receipt.user_id = "@far" + std::to_string(number) + ":example.org";
            receipt.event_id = "$far" + std::to_string(number);
            REQUIRE(db::store_receipt(store, std::move(receipt)));
        }

        WHEN("the user syncs")
        {
            auto const before = store.receipt_rows_examined.value();
            auto const synced =
                hs::handle_client_server_request(runtime, {"GET", "/_matrix/client/v3/sync", token, {}}, false);
            auto const examined = store.receipt_rows_examined.value() - before;

            THEN("the receipt rows examined are bounded by the user's own room, not by the table")
            {
                REQUIRE(synced.response.status == 200U);
                REQUIRE(examined > 0U);
                REQUIRE(examined <= 8U);
            }
        }
    }
}
