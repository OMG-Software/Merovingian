// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// MSC4186 room timelines that do not hold every event: `limited`, `prev_batch`, `num_live` and
// `expanded_timeline`. Element X's room list asks for `timeline_limit: 1`, so a room built without
// these looks to the client like a conversation of one message (0.12.45).

#include "../support/room_history_fixture.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/sync/sliding_sync.hpp"
#include "merovingian/sync/sliding_sync_room_builder.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace
{

constexpr auto room_id = std::string_view{"!room:example.org"};
constexpr auto alice = std::string_view{"@alice:example.org"};

// A room alice is joined to holding 60 messages from bob, $m101 (oldest) to $m160 (newest), at
// stream orderings 101 to 160.
[[nodiscard]] auto sixty_message_room() -> merovingian::database::PersistentStore
{
    auto store = merovingian::database::PersistentStore{};
    for (auto ordering = std::uint64_t{101U}; ordering <= 160U; ++ordering)
    {
        store.events.push_back({"$m" + std::to_string(ordering),
                                std::string{room_id},
                                "@bob:example.org",
                                std::string{R"({"type":"m.room.message","sender":"@bob:example.org",)"} +
                                    R"("room_id":"!room:example.org","content":{"body":"message )" +
                                    std::to_string(ordering) + R"("}})",
                                1U,
                                ordering,
                                {},
                                {},
                                {}});
    }
    // The fixture writes events straight into the store, so record the state group the room
    // service would have: the history-visibility filter (CSAZ-3) hides an event with no state.
    merovingian::tests::record_joined_state_for_room(store, room_id, alice);
    return store;
}

// True when the pre-serialised timeline event holds exactly this event ID.
[[nodiscard]] auto holds(std::string const& json, std::string_view event_id) -> bool
{
    return json.find("\"" + std::string{event_id} + "\"") != std::string::npos;
}

[[nodiscard]] auto timeline_holds(merovingian::sync::SlidingSyncRoomResponse const& resp, std::string_view event_id)
    -> bool
{
    return std::ranges::any_of(resp.timeline_json, [&](std::string const& json) {
        return holds(json, event_id);
    });
}

[[nodiscard]] auto with_limit(std::uint64_t timeline_limit) -> merovingian::sync::SlidingSyncRoomSubscription
{
    auto sub = merovingian::sync::SlidingSyncRoomSubscription{};
    sub.timeline_limit = timeline_limit;
    return sub;
}

} // namespace

// MSC4186 §rooms[roomId] `limited`: "True if there are more events since the previous sync than were
// included in the `timeline` field, or that the client should paginate to fetch more events." and
// `prev_batch`: "A token that can be passed as a start parameter to the `/rooms/<room_id>/messages`
// API to retrieve earlier messages."
SCENARIO("Sliding sync marks a truncated initial room timeline limited and hands back a prev_batch",
         "[sync][sliding-sync][room-builder][timeline-gap]")
{
    GIVEN("a room with 60 messages and Element X's room-list timeline_limit of 1")
    {
        auto runtime = merovingian::homeserver::HomeserverRuntime{};
        auto const store = sixty_message_room();

        WHEN("the room is built for the first time on the connection")
        {
            auto const resp =
                merovingian::sync::build_room_response(runtime, room_id, alice, with_limit(1U), 0U, true, store);

            THEN("only the newest message is sent, the timeline is limited, and prev_batch pages back from it")
            {
                REQUIRE(resp.timeline_json.size() == 1U);
                REQUIRE(timeline_holds(resp, "$m160"));
                REQUIRE(resp.limited);
                // /messages?dir=b returns the events strictly older than `from`.
                REQUIRE(resp.prev_batch == std::optional<std::string>{"160"});
                REQUIRE_FALSE(resp.expanded_timeline);
            }
        }
    }
}

SCENARIO("Sliding sync does not mark a room timeline limited when every event fits",
         "[sync][sliding-sync][room-builder][timeline-gap]")
{
    GIVEN("a room with 60 messages and a timeline_limit of 100")
    {
        auto runtime = merovingian::homeserver::HomeserverRuntime{};
        auto const store = sixty_message_room();

        WHEN("the room is built for the first time on the connection")
        {
            auto const resp =
                merovingian::sync::build_room_response(runtime, room_id, alice, with_limit(100U), 0U, true, store);

            THEN("every message is sent oldest first and the timeline is not limited")
            {
                REQUIRE(resp.timeline_json.size() == 60U);
                REQUIRE(holds(resp.timeline_json.front(), "$m101"));
                REQUIRE(holds(resp.timeline_json.back(), "$m160"));
                REQUIRE_FALSE(resp.limited);
                REQUIRE(resp.prev_batch == std::optional<std::string>{"101"});
            }
        }
    }
}

// MSC4186 §rooms[roomId] `num_live`: "The number of timeline events which have 'just occurred' and are
// not historical, i.e. that have happened since the previous sync request."
SCENARIO("Sliding sync marks an incremental room timeline limited when more arrived than the limit",
         "[sync][sliding-sync][room-builder][timeline-gap]")
{
    GIVEN("a room whose connection last saw it at $m150, so ten messages are new")
    {
        auto runtime = merovingian::homeserver::HomeserverRuntime{};
        auto const store = sixty_message_room();

        WHEN("the room is built incrementally with a timeline_limit of 5")
        {
            auto const resp =
                merovingian::sync::build_room_response(runtime, room_id, alice, with_limit(5U), 150U, false, store);

            THEN("the newest five are sent as live, the gap is flagged, and prev_batch starts at the oldest sent")
            {
                REQUIRE(resp.timeline_json.size() == 5U);
                REQUIRE(holds(resp.timeline_json.front(), "$m156"));
                REQUIRE(holds(resp.timeline_json.back(), "$m160"));
                REQUIRE(resp.limited);
                REQUIRE(resp.prev_batch == std::optional<std::string>{"156"});
                REQUIRE(resp.num_live == 5U);
            }
        }

        WHEN("the room is built incrementally with room for every new message")
        {
            auto const resp =
                merovingian::sync::build_room_response(runtime, room_id, alice, with_limit(20U), 150U, false, store);

            THEN("all ten new messages are sent as live and the timeline is not limited")
            {
                REQUIRE(resp.timeline_json.size() == 10U);
                REQUIRE_FALSE(resp.limited);
                REQUIRE(resp.num_live == 10U);
            }
        }
    }
}

// MSC4186 "Changes to `timeline_limit`": "if the `timeline_limit` has increased (to say `N`) and the
// server has not previously sent down all of the latest `N` events on the connection, the server
// SHOULD send down the latest `N` events even if *some* of the events have previously been sent."
// "If the server does return events that predate the last time the room was sent to the client, it
// MUST set the `expanded_timeline` to `true`."
SCENARIO("Sliding sync resends the latest room events when the timeline_limit grows",
         "[sync][sliding-sync][room-builder][timeline-gap]")
{
    GIVEN("a room the connection last sent at $m160")
    {
        auto runtime = merovingian::homeserver::HomeserverRuntime{};
        auto const store = sixty_message_room();

        WHEN("the room is built with a timeline_limit of 50 and the timeline expanded")
        {
            auto const resp =
                merovingian::sync::build_room_response(runtime, room_id, alice, with_limit(50U), 160U, false, store, {},
                                                       {}, merovingian::sync::TimelineExpansion::expand);

            THEN("the latest 50 messages are sent, flagged as an expanded timeline with a gap before them")
            {
                REQUIRE(resp.timeline_json.size() == 50U);
                REQUIRE(holds(resp.timeline_json.front(), "$m111"));
                REQUIRE(holds(resp.timeline_json.back(), "$m160"));
                REQUIRE(resp.expanded_timeline);
                REQUIRE(resp.limited);
                REQUIRE(resp.prev_batch == std::optional<std::string>{"111"});
                REQUIRE(resp.num_live == 0U);
            }
        }

        WHEN("the room is built with a timeline_limit of 50 and no expansion")
        {
            auto const resp =
                merovingian::sync::build_room_response(runtime, room_id, alice, with_limit(50U), 160U, false, store);

            THEN("nothing already sent is sent again")
            {
                REQUIRE(resp.timeline_json.empty());
                REQUIRE_FALSE(resp.expanded_timeline);
                REQUIRE_FALSE(resp.limited);
            }
        }
    }

    GIVEN("a room the connection last sent at $m100, before any of its messages")
    {
        auto runtime = merovingian::homeserver::HomeserverRuntime{};
        auto const store = sixty_message_room();

        WHEN("the room is built with a timeline_limit of 50 and the timeline expanded")
        {
            auto const resp =
                merovingian::sync::build_room_response(runtime, room_id, alice, with_limit(50U), 100U, false, store, {},
                                                       {}, merovingian::sync::TimelineExpansion::expand);

            THEN("nothing returned predates the last send, so the timeline is not flagged as expanded")
            {
                REQUIRE(resp.timeline_json.size() == 50U);
                REQUIRE_FALSE(resp.expanded_timeline);
                REQUIRE(resp.limited);
                REQUIRE(resp.num_live == 50U);
            }
        }
    }
}

SCENARIO("Sliding sync flags a room timeline_limit of 0 as limited with a prev_batch past the newest event",
         "[sync][sliding-sync][room-builder][timeline-gap]")
{
    GIVEN("a room with 60 messages and a timeline_limit of 0")
    {
        auto runtime = merovingian::homeserver::HomeserverRuntime{};
        auto const store = sixty_message_room();

        WHEN("the room is built for the first time on the connection")
        {
            auto const resp =
                merovingian::sync::build_room_response(runtime, room_id, alice, with_limit(0U), 0U, true, store);

            THEN("no events are sent, and paging back from prev_batch starts at the newest message")
            {
                REQUIRE(resp.timeline_json.empty());
                REQUIRE(resp.limited);
                REQUIRE(resp.prev_batch == std::optional<std::string>{"161"});
            }
        }
    }
}

SCENARIO("Sliding sync decides from the connection whether a room's timeline_limit grows",
         "[sync][sliding-sync][room-builder][timeline-gap]")
{
    GIVEN("a connection that sent !seen with a timeline_limit of 1, and !unrecorded without a recorded limit")
    {
        auto conn = merovingian::sync::SlidingSyncConnectionState{};
        conn.rooms_seen["!seen:example.org"] = 10U;
        conn.room_timeline_limits["!seen:example.org"] = 1U;
        conn.rooms_seen["!unrecorded:example.org"] = 10U;

        WHEN("each room is asked about")
        {
            auto const grows = merovingian::sync::timeline_limit_expands(conn, "!seen:example.org", 50U);
            auto const same = merovingian::sync::timeline_limit_expands(conn, "!seen:example.org", 1U);
            auto const shrinks = merovingian::sync::timeline_limit_expands(conn, "!seen:example.org", 0U);
            auto const unknown = merovingian::sync::timeline_limit_expands(conn, "!unrecorded:example.org", 1U);
            auto const unseen = merovingian::sync::timeline_limit_expands(conn, "!new:example.org", 50U);

            THEN("only a seen room asked for more than it was last sent with, or with no record, expands")
            {
                REQUIRE(grows);
                REQUIRE_FALSE(same);
                REQUIRE_FALSE(shrinks);
                // MSC4186: "If the server does not know if it has sent down all events it SHOULD send
                // down the latest `N` events."
                REQUIRE(unknown);
                // A room the connection never sent is initial, not expanded.
                REQUIRE_FALSE(unseen);
            }
        }
    }
}
