// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |      APPLICATION SERVICE EPHEMERAL DATA — EVENT SHAPES AND QUEUE        |
// |                                                                         |
// |  Spec: Matrix Application Service API v1.19, "Pushing ephemeral data"  |
// |  URL:  ../../docs/matrix-v1.19-spec/application-service-api.md          |
// |                                                                         |
// |  Pure, network-free coverage of the three ephemeral event shapes and of |
// |  the bounded, coalescing per-appservice queue (ADR-0190).               |
// +-------------------------------------------------------------------------+

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/homeserver/appservice_ephemeral.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

using merovingian::homeserver::AppserviceEphemeralItem;
using merovingian::homeserver::AppserviceEphemeralQueue;
using merovingian::homeserver::make_presence_ephemeral_event;
using merovingian::homeserver::make_receipt_ephemeral_event;
using merovingian::homeserver::make_typing_ephemeral_event;
using merovingian::homeserver::push_appservice_ephemeral;

// Spec: "m.typing: MUST be sent to the application service under the same rules as regular events ... The
// data MUST use the same format as the client-server API, with the addition of a room_id property at the
// top level to identify the room that they were sent in."
SCENARIO("a typing ephemeral event has the client-server format plus a top-level room_id",
         "[appservice][ephemeral][r08]")
{
    GIVEN("two users typing in a room")
    {
        WHEN("the event is built")
        {
            auto const event = make_typing_ephemeral_event("!room:example.org", {"@a:example.org", "@b:example.org"});

            THEN("it is m.typing with user_ids in content and the room_id beside it")
            {
                REQUIRE(event == R"({"content":{"user_ids":["@a:example.org","@b:example.org"]},)"
                                 R"("room_id":"!room:example.org","type":"m.typing"})");
            }
        }
    }

    GIVEN("nobody typing any more")
    {
        WHEN("the event is built")
        {
            auto const event = make_typing_ephemeral_event("!room:example.org", {});

            THEN("it carries an empty user_ids list, which is how the stop is announced")
            {
                REQUIRE(event == R"({"content":{"user_ids":[]},"room_id":"!room:example.org","type":"m.typing"})");
            }
        }
    }
}

// Spec: "m.receipt: ... The data MUST use the same format as the client-server API, with the addition of a
// room_id property at the top level."
SCENARIO("a receipt ephemeral event has the client-server format plus a top-level room_id",
         "[appservice][ephemeral][r08]")
{
    GIVEN("an unthreaded read receipt")
    {
        auto receipt = merovingian::database::PersistentReceipt{};
        receipt.room_id = "!room:example.org";
        receipt.receipt_type = "m.read";
        receipt.user_id = "@a:example.org";
        receipt.event_id = "$event:example.org";
        receipt.ts = 1234U;

        WHEN("the event is built")
        {
            auto const event = make_receipt_ephemeral_event(receipt);

            THEN("content is keyed by event id, receipt type and user, and room_id is beside it")
            {
                REQUIRE(event == R"({"content":{"$event:example.org":{"m.read":{"@a:example.org":{"ts":1234}}}},)"
                                 R"("room_id":"!room:example.org","type":"m.receipt"})");
            }
        }
    }

    GIVEN("a threaded read receipt")
    {
        auto receipt = merovingian::database::PersistentReceipt{};
        receipt.room_id = "!room:example.org";
        receipt.receipt_type = "m.read";
        receipt.user_id = "@a:example.org";
        receipt.event_id = "$event:example.org";
        receipt.ts = 99U;
        receipt.thread_id = "main";

        WHEN("the event is built")
        {
            auto const event = make_receipt_ephemeral_event(receipt);

            THEN("the receipt carries its thread_id, as the client-server format does")
            {
                REQUIRE(event.find(R"("thread_id":"main")") != std::string::npos);
                REQUIRE(event.find(R"("room_id":"!room:example.org")") != std::string::npos);
            }
        }
    }
}

// Spec: "m.presence: MUST be sent ... if the data would apply contextually."
SCENARIO("a presence ephemeral event has the client-server m.presence format", "[appservice][ephemeral][r08]")
{
    GIVEN("a presence state and the user's profile")
    {
        auto presence = merovingian::database::PersistentPresence{};
        presence.user_id = "@a:example.org";
        presence.presence = "online";
        presence.status_msg = "around";
        presence.last_active_ago = 5000;
        presence.currently_active = true;
        auto profile = merovingian::database::PersistentProfile{};
        profile.user_id = "@a:example.org";
        profile.displayname = "Alice";
        profile.avatar_url = "mxc://example.org/abc";

        WHEN("the event is built")
        {
            auto const event = make_presence_ephemeral_event(presence, profile);

            THEN("it names the user as sender and has no room_id, since presence is not room-scoped")
            {
                REQUIRE(event == R"({"content":{"avatar_url":"mxc://example.org/abc","currently_active":true,)"
                                 R"("displayname":"Alice","last_active_ago":5000,"presence":"online",)"
                                 R"("status_msg":"around"},"sender":"@a:example.org","type":"m.presence"})");
            }
        }
    }

    GIVEN("a presence state with no status message and no profile")
    {
        auto presence = merovingian::database::PersistentPresence{};
        presence.user_id = "@a:example.org";
        presence.presence = "offline";

        WHEN("the event is built")
        {
            auto const event = make_presence_ephemeral_event(presence, std::nullopt);

            THEN("the optional members are left out")
            {
                REQUIRE(event.find("status_msg") == std::string::npos);
                REQUIRE(event.find("displayname") == std::string::npos);
                REQUIRE(event.find("avatar_url") == std::string::npos);
                REQUIRE(event.find(R"("presence":"offline")") != std::string::npos);
            }
        }
    }
}

// ADR-0190: a newer item describing the same thing replaces the older, and the queue is bounded.
SCENARIO("the ephemeral queue keeps the latest item per key and is bounded", "[appservice][ephemeral][r08][boundary]")
{
    GIVEN("a queue holding the typing state of one room")
    {
        auto queue = AppserviceEphemeralQueue{};
        push_appservice_ephemeral(queue, {"typing|!a", "first"}, 8U);
        push_appservice_ephemeral(queue, {"presence|@u", "presence"}, 8U);

        WHEN("the same room's typing state is queued again")
        {
            push_appservice_ephemeral(queue, {"typing|!a", "second"}, 8U);

            THEN("the older item is replaced, not duplicated, and the newer one takes the back of the queue")
            {
                REQUIRE(queue.items.size() == 2U);
                REQUIRE(queue.items.front().json == "presence");
                REQUIRE(queue.items.back().json == "second");
                REQUIRE(queue.dropped == 0U);
            }
        }
    }

    GIVEN("a queue at its capacity of three")
    {
        auto queue = AppserviceEphemeralQueue{};
        for (auto index = 0; index < 3; ++index)
        {
            push_appservice_ephemeral(queue, {"key" + std::to_string(index), "item" + std::to_string(index)}, 3U);
        }

        WHEN("an item with a different key arrives")
        {
            push_appservice_ephemeral(queue, {"key3", "item3"}, 3U);

            THEN("the oldest is dropped and counted, and the queue stays at capacity")
            {
                REQUIRE(queue.items.size() == 3U);
                REQUIRE(queue.items.front().json == "item1");
                REQUIRE(queue.items.back().json == "item3");
                REQUIRE(queue.dropped == 1U);
            }
        }

        WHEN("an item replaces one already queued")
        {
            push_appservice_ephemeral(queue, {"key1", "again"}, 3U);

            THEN("nothing is dropped: a replacement does not grow the queue")
            {
                REQUIRE(queue.items.size() == 3U);
                REQUIRE(queue.dropped == 0U);
            }
        }
    }

    GIVEN("a flood of distinct keys far past the capacity")
    {
        auto queue = AppserviceEphemeralQueue{};

        WHEN("ten thousand are queued")
        {
            for (auto index = 0; index < 10000; ++index)
            {
                push_appservice_ephemeral(queue, {"key" + std::to_string(index), "x"}, 64U);
            }

            THEN("the queue never exceeds its capacity and every excess item was counted")
            {
                REQUIRE(queue.items.size() == 64U);
                REQUIRE(queue.dropped == 10000U - 64U);
            }
        }
    }
}
