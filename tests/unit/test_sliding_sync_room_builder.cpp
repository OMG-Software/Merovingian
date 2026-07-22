// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/sync/sliding_sync.hpp"
#include "merovingian/sync/sliding_sync_room_builder.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace
{

auto append_event(merovingian::database::PersistentStore& store, std::string_view event_id, std::string_view room_id,
                  std::string_view json, std::uint64_t stream_ordering) -> void
{
    store.events.push_back({
        std::string{event_id},
        std::string{room_id},
        "@alice:example.org",
        std::string{json},
        1U,
        stream_ordering,
        {},
        {},
        {},
    });
}

auto append_state(merovingian::database::PersistentStore& store, std::string_view room_id, std::string_view event_type,
                  std::string_view state_key, std::string_view event_id) -> void
{
    store.state.push_back({
        std::string{room_id},
        std::string{event_type},
        std::string{state_key},
        std::string{event_id},
    });
}

} // namespace

// ── required_state: initial vs. incremental filtering ────────────────────────

SCENARIO("Sliding sync room builder includes all matching required_state on initial sync",
         "[sync][sliding-sync][room-builder]")
{
    GIVEN("a room with two state events — create (ordering=3) and name (ordering=5)")
    {
        auto runtime = merovingian::homeserver::HomeserverRuntime{};
        auto store = merovingian::database::PersistentStore{};

        append_event(store, "$create", "!room:example.org", R"({"type":"m.room.create","content":{}})", 3U);
        append_state(store, "!room:example.org", "m.room.create", "", "$create");

        append_event(store, "$name", "!room:example.org", R"({"type":"m.room.name","content":{"name":"Test Room"}})",
                     5U);
        append_state(store, "!room:example.org", "m.room.name", "", "$name");

        auto sub = merovingian::sync::SlidingSyncRoomSubscription{};
        sub.required_state = {
            {"m.room.create", ""},
            {"m.room.name",   ""}
        };

        WHEN("build_room_response is called with is_initial=true and since_event_ordering=0")
        {
            auto const resp = merovingian::sync::build_room_response(runtime, "!room:example.org", "@alice:example.org",
                                                                     sub, 0U, true, store);

            THEN("required_state_json contains both state events")
            {
                REQUIRE(resp.required_state_json.size() == 2U);
                REQUIRE(resp.initial == true);
            }
        }
    }
}

SCENARIO("Sliding sync room builder omits required_state that has not changed since the pos",
         "[sync][sliding-sync][room-builder]")
{
    GIVEN("a room with a name state event at ordering=5 and since_event_ordering=10")
    {
        auto runtime = merovingian::homeserver::HomeserverRuntime{};
        auto store = merovingian::database::PersistentStore{};

        append_event(store, "$name", "!room:example.org", R"({"type":"m.room.name","content":{"name":"Old Name"}})",
                     5U);
        append_state(store, "!room:example.org", "m.room.name", "", "$name");

        auto sub = merovingian::sync::SlidingSyncRoomSubscription{};
        sub.required_state = {
            {"m.room.name", ""}
        };

        WHEN("build_room_response is called with is_initial=false and since_event_ordering=10")
        {
            auto const resp = merovingian::sync::build_room_response(runtime, "!room:example.org", "@alice:example.org",
                                                                     sub, 10U, false, store);

            THEN("required_state_json is empty because the state predates the pos")
            {
                REQUIRE(resp.required_state_json.empty());
                REQUIRE(resp.initial == false);
            }
        }
    }
}

SCENARIO("Sliding sync room builder includes only state events that changed after the pos",
         "[sync][sliding-sync][room-builder]")
{
    GIVEN("a room with a name event at ordering=5 (old) and a topic event at ordering=15 (new)")
    {
        auto runtime = merovingian::homeserver::HomeserverRuntime{};
        auto store = merovingian::database::PersistentStore{};

        append_event(store, "$name", "!room:example.org", R"({"type":"m.room.name","content":{"name":"Old Name"}})",
                     5U);
        append_state(store, "!room:example.org", "m.room.name", "", "$name");

        append_event(store, "$topic", "!room:example.org", R"({"type":"m.room.topic","content":{"topic":"New Topic"}})",
                     15U);
        append_state(store, "!room:example.org", "m.room.topic", "", "$topic");

        auto sub = merovingian::sync::SlidingSyncRoomSubscription{};
        sub.required_state = {
            {"m.room.name",  ""},
            {"m.room.topic", ""}
        };

        WHEN("build_room_response is called with is_initial=false and since_event_ordering=10")
        {
            auto const resp = merovingian::sync::build_room_response(runtime, "!room:example.org", "@alice:example.org",
                                                                     sub, 10U, false, store);

            THEN("required_state_json contains only the topic event (ordering > pos) not the name event")
            {
                REQUIRE(resp.required_state_json.size() == 1U);
                REQUIRE(resp.required_state_json.front().find("m.room.topic") != std::string::npos);
            }
        }
    }
}

SCENARIO("Sliding sync room builder produces no updates when nothing changed since the pos",
         "[sync][sliding-sync][room-builder]")
{
    GIVEN("a room with all events and state at ordering <= 10 and since_event_ordering=10")
    {
        auto runtime = merovingian::homeserver::HomeserverRuntime{};
        auto store = merovingian::database::PersistentStore{};

        append_event(store, "$create", "!room:example.org", R"({"type":"m.room.create","content":{}})", 3U);
        append_state(store, "!room:example.org", "m.room.create", "", "$create");

        append_event(store, "$name", "!room:example.org", R"({"type":"m.room.name","content":{"name":"Unchanged"}})",
                     5U);
        append_state(store, "!room:example.org", "m.room.name", "", "$name");

        store.memberships = {
            {"!room:example.org", "@alice:example.org", "join", 3U}
        };

        auto sub = merovingian::sync::SlidingSyncRoomSubscription{};
        sub.required_state = {
            {"*", "*"}
        };
        sub.timeline_limit = 50U;

        WHEN("build_room_response is called with is_initial=false and since_event_ordering=10")
        {
            auto const resp = merovingian::sync::build_room_response(runtime, "!room:example.org", "@alice:example.org",
                                                                     sub, 10U, false, store);

            THEN("the response has no updates: empty required_state, empty timeline, zero counts")
            {
                REQUIRE(resp.required_state_json.empty());
                REQUIRE(resp.timeline_json.empty());
                REQUIRE(resp.notification_count.value_or(0U) == 0U);
                REQUIRE(resp.highlight_count.value_or(0U) == 0U);
            }
        }
    }
}

SCENARIO("Sliding sync room builder populates timeline_json for new events after the pos",
         "[sync][sliding-sync][room-builder]")
{
    GIVEN("a room with one message event at ordering=15 and since_event_ordering=10")
    {
        auto runtime = merovingian::homeserver::HomeserverRuntime{};
        auto store = merovingian::database::PersistentStore{};

        append_event(store, "$msg", "!room:example.org", R"({"type":"m.room.message","content":{"body":"hello"}})",
                     15U);

        auto sub = merovingian::sync::SlidingSyncRoomSubscription{};
        sub.timeline_limit = 20U;

        WHEN("build_room_response is called with is_initial=false and since_event_ordering=10")
        {
            auto const resp = merovingian::sync::build_room_response(runtime, "!room:example.org", "@alice:example.org",
                                                                     sub, 10U, false, store);

            THEN("timeline_json contains the new event")
            {
                REQUIRE(resp.timeline_json.size() == 1U);
                REQUIRE(resp.timeline_json.front().find("m.room.message") != std::string::npos);
            }
        }
    }
}

SCENARIO("Sliding sync room builder wildcard required_state includes all matching changed state",
         "[sync][sliding-sync][room-builder]")
{
    GIVEN("a room with create (ordering=3) and name (ordering=15) — name changed after pos=10")
    {
        auto runtime = merovingian::homeserver::HomeserverRuntime{};
        auto store = merovingian::database::PersistentStore{};

        append_event(store, "$create", "!room:example.org", R"({"type":"m.room.create","content":{}})", 3U);
        append_state(store, "!room:example.org", "m.room.create", "", "$create");

        append_event(store, "$name", "!room:example.org", R"({"type":"m.room.name","content":{"name":"New Name"}})",
                     15U);
        append_state(store, "!room:example.org", "m.room.name", "", "$name");

        auto sub = merovingian::sync::SlidingSyncRoomSubscription{};
        sub.required_state = {
            {"*", "*"}
        };

        WHEN("build_room_response is called with is_initial=false and since_event_ordering=10")
        {
            auto const resp = merovingian::sync::build_room_response(runtime, "!room:example.org", "@alice:example.org",
                                                                     sub, 10U, false, store);

            THEN("only the name event (ordering=15 > pos=10) appears in required_state_json")
            {
                REQUIRE(resp.required_state_json.size() == 1U);
                REQUIRE(resp.required_state_json.front().find("m.room.name") != std::string::npos);
            }
        }
    }
}

// ── required_state sentinels: "$ME" and "$LAZY" (matrix-rust-sdk / Element X) ──
//
// matrix-rust-sdk's RoomListService always requests
// required_state=[..., ["m.room.member","$LAZY"], ["m.room.member","$ME"], ...]
// (crates/matrix-sdk-ui/src/room_list_service/mod.rs, DEFAULT_REQUIRED_STATE).
// Before this, matches_required_state_pair did plain string equality, so
// neither sentinel ever matched a real state_key (always a user ID) —
// Element X never received any m.room.member events from sliding sync.

SCENARIO("Sliding sync room builder resolves required_state \"$ME\" to the requesting user's own member event",
         "[sync][sliding-sync][room-builder][lazy-loading]")
{
    GIVEN("a room where alice (the requester) and bob have both joined")
    {
        auto runtime = merovingian::homeserver::HomeserverRuntime{};
        auto store = merovingian::database::PersistentStore{};

        append_event(store, "$alice-join", "!room:example.org",
                     R"({"type":"m.room.member","sender":"@alice:example.org",)"
                     R"("state_key":"@alice:example.org","content":{"membership":"join"}})",
                     1U);
        append_state(store, "!room:example.org", "m.room.member", "@alice:example.org", "$alice-join");

        append_event(store, "$bob-join", "!room:example.org",
                     R"({"type":"m.room.member","sender":"@bob:example.org",)"
                     R"("state_key":"@bob:example.org","content":{"membership":"join"}})",
                     2U);
        append_state(store, "!room:example.org", "m.room.member", "@bob:example.org", "$bob-join");

        auto sub = merovingian::sync::SlidingSyncRoomSubscription{};
        sub.required_state = {
            {"m.room.member", "$ME"}
        };

        WHEN("alice's initial sliding sync is built")
        {
            auto const resp = merovingian::sync::build_room_response(runtime, "!room:example.org", "@alice:example.org",
                                                                     sub, 0U, true, store);

            THEN("required_state_json contains only alice's own member event")
            {
                REQUIRE(resp.required_state_json.size() == 1U);
                REQUIRE(resp.required_state_json.front().find("@alice:example.org") != std::string::npos);
            }
        }
    }
}

SCENARIO("Sliding sync room builder scopes required_state \"$LAZY\" to timeline senders on initial sync",
         "[sync][sliding-sync][room-builder][lazy-loading]")
{
    GIVEN("alice, bob, and carol have joined a room, but only bob has sent a timeline message")
    {
        auto runtime = merovingian::homeserver::HomeserverRuntime{};
        auto store = merovingian::database::PersistentStore{};

        append_event(store, "$alice-join", "!room:example.org",
                     R"({"type":"m.room.member","sender":"@alice:example.org",)"
                     R"("state_key":"@alice:example.org","content":{"membership":"join"}})",
                     1U);
        append_state(store, "!room:example.org", "m.room.member", "@alice:example.org", "$alice-join");

        append_event(store, "$bob-join", "!room:example.org",
                     R"({"type":"m.room.member","sender":"@bob:example.org",)"
                     R"("state_key":"@bob:example.org","content":{"membership":"join"}})",
                     2U);
        append_state(store, "!room:example.org", "m.room.member", "@bob:example.org", "$bob-join");

        append_event(store, "$carol-join", "!room:example.org",
                     R"({"type":"m.room.member","sender":"@carol:example.org",)"
                     R"("state_key":"@carol:example.org","content":{"membership":"join"}})",
                     3U);
        append_state(store, "!room:example.org", "m.room.member", "@carol:example.org", "$carol-join");

        append_event(store, "$bob-msg", "!room:example.org",
                     R"({"type":"m.room.message","sender":"@bob:example.org","content":{"body":"hi"}})", 10U);

        auto sub = merovingian::sync::SlidingSyncRoomSubscription{};
        sub.required_state = {
            {"m.room.member", "$LAZY"}
        };
        // Element X's real default (DEFAULT_LIST_TIMELINE_LIMIT = 1). A
        // generous limit would let the join events above (which are
        // themselves timeline events) survive truncation and legitimately
        // make alice/carol lazy-relevant too, since anyone whose own
        // membership event is part of the *delivered* timeline is relevant —
        // this test is specifically about the truncated-timeline case, where
        // only the most recent event (bob's message) is delivered.
        sub.timeline_limit = 1U;

        WHEN("alice's initial sliding sync is built")
        {
            auto const resp = merovingian::sync::build_room_response(runtime, "!room:example.org", "@alice:example.org",
                                                                     sub, 0U, true, store);

            THEN("required_state_json contains only bob's member event — not alice's or carol's")
            {
                REQUIRE(resp.required_state_json.size() == 1U);
                REQUIRE(resp.required_state_json.front().find("@bob:example.org") != std::string::npos);
            }

            THEN("lazy_members_included records bob as newly delivered")
            {
                REQUIRE(resp.lazy_members_included == std::unordered_set<std::string>{"@bob:example.org"});
            }
        }
    }
}

SCENARIO("Sliding sync room builder's \"$LAZY\" bypasses the delta floor for a member new to the connection",
         "[sync][sliding-sync][room-builder][lazy-loading]")
{
    // dave's own membership event (ordering=2) predates the incremental floor
    // (ordering=40): a plain required_state match would skip it as
    // "unchanged since pos". But dave has never been lazily delivered on this
    // connection and just sent his first message in view (ordering=50), so
    // his membership must be delivered now regardless of the floor.
    GIVEN("dave joined long ago and just sent his first message after the connection's since-floor")
    {
        auto runtime = merovingian::homeserver::HomeserverRuntime{};
        auto store = merovingian::database::PersistentStore{};

        append_event(store, "$dave-join", "!room:example.org",
                     R"({"type":"m.room.member","sender":"@dave:example.org",)"
                     R"("state_key":"@dave:example.org","content":{"membership":"join"}})",
                     2U);
        append_state(store, "!room:example.org", "m.room.member", "@dave:example.org", "$dave-join");

        append_event(store, "$dave-msg", "!room:example.org",
                     R"({"type":"m.room.message","sender":"@dave:example.org","content":{"body":"hello"}})", 50U);

        auto sub = merovingian::sync::SlidingSyncRoomSubscription{};
        sub.required_state = {
            {"m.room.member", "$LAZY"}
        };
        sub.timeline_limit = 20U; // timeline has 1 event — not limited/truncated

        WHEN("dave has never been lazily delivered on this connection")
        {
            auto const already_sent = std::unordered_set<std::string>{};
            auto const resp = merovingian::sync::build_room_response(runtime, "!room:example.org", "@alice:example.org",
                                                                     sub, 40U, false, store, already_sent);

            THEN("dave's old member event is still included, bypassing the since-floor")
            {
                REQUIRE(resp.required_state_json.size() == 1U);
                REQUIRE(resp.required_state_json.front().find("@dave:example.org") != std::string::npos);
                REQUIRE(resp.lazy_members_included == std::unordered_set<std::string>{"@dave:example.org"});
            }
        }

        WHEN("dave was already lazily delivered on a prior response on this connection")
        {
            auto const already_sent = std::unordered_set<std::string>{"@dave:example.org"};
            auto const resp = merovingian::sync::build_room_response(runtime, "!room:example.org", "@alice:example.org",
                                                                     sub, 40U, false, store, already_sent);

            THEN("dave's unchanged member event is not re-sent")
            {
                REQUIRE(resp.required_state_json.empty());
                REQUIRE(resp.lazy_members_included.empty());
            }
        }
    }
}

SCENARIO("Sliding sync room builder resolves \"$LAZY\" and \"$ME\" together, matching Element X's real request",
         "[sync][sliding-sync][room-builder][lazy-loading][elementx]")
{
    // matrix-rust-sdk's DEFAULT_REQUIRED_STATE requests both sentinels in the
    // same required_state array; they must not interfere with each other.
    GIVEN("alice (the requester) and bob have joined, and bob has sent a timeline message")
    {
        auto runtime = merovingian::homeserver::HomeserverRuntime{};
        auto store = merovingian::database::PersistentStore{};

        append_event(store, "$alice-join", "!room:example.org",
                     R"({"type":"m.room.member","sender":"@alice:example.org",)"
                     R"("state_key":"@alice:example.org","content":{"membership":"join"}})",
                     1U);
        append_state(store, "!room:example.org", "m.room.member", "@alice:example.org", "$alice-join");

        append_event(store, "$bob-join", "!room:example.org",
                     R"({"type":"m.room.member","sender":"@bob:example.org",)"
                     R"("state_key":"@bob:example.org","content":{"membership":"join"}})",
                     2U);
        append_state(store, "!room:example.org", "m.room.member", "@bob:example.org", "$bob-join");

        append_event(store, "$bob-msg", "!room:example.org",
                     R"({"type":"m.room.message","sender":"@bob:example.org","content":{"body":"hi"}})", 10U);

        auto sub = merovingian::sync::SlidingSyncRoomSubscription{};
        sub.required_state = {
            {"m.room.member", "$LAZY"},
            {"m.room.member", "$ME"  }
        };
        sub.timeline_limit = 20U;

        WHEN("alice's initial sliding sync is built")
        {
            auto const resp = merovingian::sync::build_room_response(runtime, "!room:example.org", "@alice:example.org",
                                                                     sub, 0U, true, store);

            THEN("required_state_json contains both alice's own member event and bob's lazily-loaded one")
            {
                REQUIRE(resp.required_state_json.size() == 2U);
                auto const has_alice = std::ranges::any_of(resp.required_state_json, [](std::string const& json) {
                    return json.find("@alice:example.org") != std::string::npos;
                });
                auto const has_bob = std::ranges::any_of(resp.required_state_json, [](std::string const& json) {
                    return json.find("@bob:example.org") != std::string::npos;
                });
                REQUIRE(has_alice);
                REQUIRE(has_bob);
            }
        }
    }
}

// ── notification / highlight counts vs read receipts (#417) ──────────────────

SCENARIO("Sliding sync notification counts are baselined on the user's read receipt, not the sync position",
         "[sync][sliding-sync][room-builder][receipts]")
{
    GIVEN("a room with three messages from bob and alice's read receipt on the second")
    {
        auto runtime = merovingian::homeserver::HomeserverRuntime{};
        auto store = merovingian::database::PersistentStore{};

        auto const message_json = R"({"type":"m.room.message","sender":"@bob:example.org",)"
                                  R"("content":{"body":"hi"}})";
        store.events.push_back({"$m1", "!room:example.org", "@bob:example.org", message_json, 1U, 10U, {}, {}, {}});
        store.events.push_back({"$m2", "!room:example.org", "@bob:example.org", message_json, 1U, 20U, {}, {}, {}});
        store.events.push_back({"$m3", "!room:example.org", "@bob:example.org", message_json, 1U, 30U, {}, {}, {}});

        auto receipt = merovingian::homeserver::InboundReceipt{};
        receipt.room_id = "!room:example.org";
        receipt.receipt_type = "m.read";
        receipt.user_id = "@alice:example.org";
        receipt.event_id = "$m2";
        receipt.stream_id = 1U;
        runtime.receipts.push_back(receipt);

        auto sub = merovingian::sync::SlidingSyncRoomSubscription{};
        sub.timeline_limit = 20U;

        WHEN("alice's initial sync response is built (since ordering 0)")
        {
            auto const resp = merovingian::sync::build_room_response(runtime, "!room:example.org", "@alice:example.org",
                                                                     sub, 0U, true, store);

            THEN("only the message after the read receipt counts as unread")
            {
                // Regression for #417: the count previously used the sync
                // position, so an initial sync reported every message ever
                // sent in the room as unread.
                REQUIRE(resp.notification_count.value_or(99U) == 1U);
            }
        }

        WHEN("the read-receipt baseline is computed directly")
        {
            auto const ordering =
                merovingian::sync::read_receipt_ordering(runtime, store, "!room:example.org", "@alice:example.org");

            THEN("it is the stream ordering of the receipted event")
            {
                REQUIRE(ordering == 20U);
            }

            THEN("a user with no receipt has a zero baseline")
            {
                REQUIRE(merovingian::sync::read_receipt_ordering(runtime, store, "!room:example.org",
                                                                 "@carol:example.org") == 0U);
            }
        }
    }
}

SCENARIO("Sliding sync notification counts exclude the user's own messages",
         "[sync][sliding-sync][room-builder][receipts]")
{
    GIVEN("a room where alice has sent the only message and has no read receipt")
    {
        auto runtime = merovingian::homeserver::HomeserverRuntime{};
        auto store = merovingian::database::PersistentStore{};

        store.events.push_back({"$own",
                                "!room:example.org",
                                "@alice:example.org",
                                R"({"type":"m.room.message","sender":"@alice:example.org",)"
                                R"("content":{"body":"mine"}})",
                                1U,
                                10U,
                                {},
                                {},
                                {}});

        auto sub = merovingian::sync::SlidingSyncRoomSubscription{};
        sub.timeline_limit = 20U;

        WHEN("alice's response is built")
        {
            auto const resp = merovingian::sync::build_room_response(runtime, "!room:example.org", "@alice:example.org",
                                                                     sub, 0U, true, store);

            THEN("her own message is not reported as an unread notification")
            {
                REQUIRE(resp.notification_count.value_or(99U) == 0U);
            }
        }
    }
}

// ── duplicate event_id keys in client-facing JSON (#457) ─────────────────────

SCENARIO("Sliding sync timeline events never carry a duplicate event_id key",
         "[sync][sliding-sync][room-builder][canonical-json]")
{
    GIVEN("a stored event whose JSON already contains an event_id field (v1-v3 room format)")
    {
        auto runtime = merovingian::homeserver::HomeserverRuntime{};
        auto store = merovingian::database::PersistentStore{};

        store.events.push_back({"$legacy",
                                "!room:example.org",
                                "@bob:example.org",
                                R"({"event_id":"$legacy","type":"m.room.message",)"
                                R"("content":{"body":"old format"}})",
                                1U,
                                10U,
                                {},
                                {},
                                {}});

        auto sub = merovingian::sync::SlidingSyncRoomSubscription{};
        sub.timeline_limit = 20U;

        WHEN("the room response is built")
        {
            auto const resp = merovingian::sync::build_room_response(runtime, "!room:example.org", "@alice:example.org",
                                                                     sub, 0U, true, store);

            THEN("the timeline event contains exactly one event_id key")
            {
                REQUIRE(resp.timeline_json.size() == 1U);
                auto const& json = resp.timeline_json.front();
                auto count = std::size_t{0U};
                auto pos = json.find("\"event_id\"");
                while (pos != std::string::npos)
                {
                    ++count;
                    pos = json.find("\"event_id\"", pos + 1U);
                }
                REQUIRE(count == 1U);
                REQUIRE(json.find("$legacy") != std::string::npos);
            }
        }
    }
}
