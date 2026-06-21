// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/sync/sliding_sync.hpp"
#include "merovingian/sync/sliding_sync_room_builder.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace
{

auto append_event(merovingian::database::PersistentStore& store,
                  std::string_view                        event_id,
                  std::string_view                        room_id,
                  std::string_view                        json,
                  std::uint64_t                           stream_ordering) -> void
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

auto append_state(merovingian::database::PersistentStore& store,
                  std::string_view                        room_id,
                  std::string_view                        event_type,
                  std::string_view                        state_key,
                  std::string_view                        event_id) -> void
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
        auto store   = merovingian::database::PersistentStore{};

        append_event(store, "$create", "!room:example.org",
                     R"({"type":"m.room.create","content":{}})", 3U);
        append_state(store, "!room:example.org", "m.room.create", "", "$create");

        append_event(store, "$name", "!room:example.org",
                     R"({"type":"m.room.name","content":{"name":"Test Room"}})", 5U);
        append_state(store, "!room:example.org", "m.room.name", "", "$name");

        auto sub = merovingian::sync::SlidingSyncRoomSubscription{};
        sub.required_state = {{"m.room.create", ""}, {"m.room.name", ""}};

        WHEN("build_room_response is called with is_initial=true and since_event_ordering=0")
        {
            auto const resp = merovingian::sync::build_room_response(
                runtime, "!room:example.org", "@alice:example.org", sub, 0U, true, store);

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
        auto store   = merovingian::database::PersistentStore{};

        append_event(store, "$name", "!room:example.org",
                     R"({"type":"m.room.name","content":{"name":"Old Name"}})", 5U);
        append_state(store, "!room:example.org", "m.room.name", "", "$name");

        auto sub = merovingian::sync::SlidingSyncRoomSubscription{};
        sub.required_state = {{"m.room.name", ""}};

        WHEN("build_room_response is called with is_initial=false and since_event_ordering=10")
        {
            auto const resp = merovingian::sync::build_room_response(
                runtime, "!room:example.org", "@alice:example.org", sub, 10U, false, store);

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
        auto store   = merovingian::database::PersistentStore{};

        append_event(store, "$name", "!room:example.org",
                     R"({"type":"m.room.name","content":{"name":"Old Name"}})", 5U);
        append_state(store, "!room:example.org", "m.room.name", "", "$name");

        append_event(store, "$topic", "!room:example.org",
                     R"({"type":"m.room.topic","content":{"topic":"New Topic"}})", 15U);
        append_state(store, "!room:example.org", "m.room.topic", "", "$topic");

        auto sub = merovingian::sync::SlidingSyncRoomSubscription{};
        sub.required_state = {{"m.room.name", ""}, {"m.room.topic", ""}};

        WHEN("build_room_response is called with is_initial=false and since_event_ordering=10")
        {
            auto const resp = merovingian::sync::build_room_response(
                runtime, "!room:example.org", "@alice:example.org", sub, 10U, false, store);

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
        auto store   = merovingian::database::PersistentStore{};

        append_event(store, "$create", "!room:example.org",
                     R"({"type":"m.room.create","content":{}})", 3U);
        append_state(store, "!room:example.org", "m.room.create", "", "$create");

        append_event(store, "$name", "!room:example.org",
                     R"({"type":"m.room.name","content":{"name":"Unchanged"}})", 5U);
        append_state(store, "!room:example.org", "m.room.name", "", "$name");

        store.memberships = {{"!room:example.org", "@alice:example.org", "join", 3U}};

        auto sub = merovingian::sync::SlidingSyncRoomSubscription{};
        sub.required_state = {{"*", "*"}};
        sub.timeline_limit = 50U;

        WHEN("build_room_response is called with is_initial=false and since_event_ordering=10")
        {
            auto const resp = merovingian::sync::build_room_response(
                runtime, "!room:example.org", "@alice:example.org", sub, 10U, false, store);

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
        auto store   = merovingian::database::PersistentStore{};

        append_event(store, "$msg", "!room:example.org",
                     R"({"type":"m.room.message","content":{"body":"hello"}})", 15U);

        auto sub = merovingian::sync::SlidingSyncRoomSubscription{};
        sub.timeline_limit = 20U;

        WHEN("build_room_response is called with is_initial=false and since_event_ordering=10")
        {
            auto const resp = merovingian::sync::build_room_response(
                runtime, "!room:example.org", "@alice:example.org", sub, 10U, false, store);

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
        auto store   = merovingian::database::PersistentStore{};

        append_event(store, "$create", "!room:example.org",
                     R"({"type":"m.room.create","content":{}})", 3U);
        append_state(store, "!room:example.org", "m.room.create", "", "$create");

        append_event(store, "$name", "!room:example.org",
                     R"({"type":"m.room.name","content":{"name":"New Name"}})", 15U);
        append_state(store, "!room:example.org", "m.room.name", "", "$name");

        auto sub = merovingian::sync::SlidingSyncRoomSubscription{};
        sub.required_state = {{"*", "*"}};

        WHEN("build_room_response is called with is_initial=false and since_event_ordering=10")
        {
            auto const resp = merovingian::sync::build_room_response(
                runtime, "!room:example.org", "@alice:example.org", sub, 10U, false, store);

            THEN("only the name event (ordering=15 > pos=10) appears in required_state_json")
            {
                REQUIRE(resp.required_state_json.size() == 1U);
                REQUIRE(resp.required_state_json.front().find("m.room.name") != std::string::npos);
            }
        }
    }
}
