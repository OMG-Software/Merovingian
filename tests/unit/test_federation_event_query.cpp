// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation/event_query.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace
{

using merovingian::federation::RoomReadStatus;

// Room "!room:remote.example.org" has exactly one joined user, alice, whose
// server is `member_origin`. Every other server name is a stranger to the room.
constexpr auto member_origin = std::string_view{"remote.example.org"};
constexpr auto stranger_origin = std::string_view{"stranger.example.org"};
constexpr auto room_id_under_test = std::string_view{"!room:remote.example.org"};

[[nodiscard]] auto store_with_room_events() -> merovingian::database::PersistentStore
{
    auto store = merovingian::database::PersistentStore{};
    auto const room_id = std::string{"!room:remote.example.org"};
    auto const sender = std::string{"@alice:remote.example.org"};
    store.events.push_back({"$create:remote.example.org",
                            room_id,
                            sender,
                            R"({"type":"m.room.create","state_key":""})",
                            1U,
                            1U,
                            {},
                            {},
                            {}});
    store.events.push_back(
        {"$member:remote.example.org",
         room_id,
         sender,
         R"({"type":"m.room.member","state_key":"@alice:remote.example.org","content":{"membership":"join"}})",
         2U,
         2U,
         {"$create:remote.example.org"},
         {},
         {}});
    store.events.push_back({"$message:remote.example.org",
                            room_id,
                            sender,
                            R"({"type":"m.room.message"})",
                            5U,
                            3U,
                            {"$member:remote.example.org"},
                            {},
                            {}});
    store.events.push_back({"$elsewhere:remote.example.org",
                            "!other:remote.example.org",
                            sender,
                            R"({"type":"m.room.message","room":"other"})",
                            4U,
                            4U,
                            {},
                            {},
                            {}});
    store.state.push_back({room_id, "m.room.create", "", "$create:remote.example.org"});
    store.state.push_back({room_id, "m.room.member", sender, "$member:remote.example.org"});
    return store;
}

auto set_membership(merovingian::database::PersistentStore& store, std::string const& user_id,
                    std::string const& membership) -> void
{
    auto const event_id = "$member_" + user_id;
    store.events.push_back({event_id,
                            std::string{room_id_under_test},
                            user_id,
                            R"({"type":"m.room.member","state_key":")" + user_id + R"(","content":{"membership":")" +
                                membership + R"("}})",
                            3U,
                            10U,
                            {},
                            {},
                            {}});
    store.state.push_back({std::string{room_id_under_test}, "m.room.member", user_id, event_id});
}

auto set_history_visibility(merovingian::database::PersistentStore& store, std::string const& visibility) -> void
{
    store.events.push_back({"$history_visibility:remote.example.org",
                            std::string{room_id_under_test},
                            "@alice:remote.example.org",
                            R"({"type":"m.room.history_visibility","state_key":"","content":{"history_visibility":")" +
                                visibility + R"("}})",
                            3U,
                            11U,
                            {},
                            {},
                            {}});
    store.state.push_back(
        {std::string{room_id_under_test}, "m.room.history_visibility", "", "$history_visibility:remote.example.org"});
}

// A linear chain $c0 <- $c1 <- ... <- $c{count-1} in the room under test. $c0 has
// depth 1000 so it never collides with the fixture's own depths.
[[nodiscard]] auto store_with_chain(std::size_t count) -> merovingian::database::PersistentStore
{
    auto store = store_with_room_events();
    for (auto i = std::size_t{0U}; i < count; ++i)
    {
        auto prev = std::vector<std::string>{};
        if (i > 0U)
        {
            prev.push_back("$c" + std::to_string(i - 1U));
        }
        store.events.push_back({"$c" + std::to_string(i),
                                std::string{room_id_under_test},
                                "@alice:remote.example.org",
                                R"({"type":"m.room.message","content":{"body":"c)" + std::to_string(i) + R"("}})",
                                1000U + i,
                                100U + i,
                                std::move(prev),
                                {},
                                {}});
    }
    return store;
}

[[nodiscard]] auto count_occurrences(std::string const& haystack, std::string_view needle) -> std::size_t
{
    auto count = std::size_t{0U};
    for (auto at = haystack.find(needle); at != std::string::npos; at = haystack.find(needle, at + needle.size()))
    {
        ++count;
    }
    return count;
}

} // namespace

// Spec: SS API v1.19, GET /_matrix/federation/v1/event/{eventId}, plus the FED-2
// security requirement that a server outside the room is refused (403).
SCENARIO("Federation event response returns a single signed PDU to a server in the room",
         "[federation][events][query][fed2]")
{
    GIVEN("a store containing the requested event and a joined user from the requesting server")
    {
        auto const store = store_with_room_events();

        WHEN("the event is queried by id by that server")
        {
            auto const result = merovingian::federation::build_event_response(store, "$message:remote.example.org",
                                                                              "local.example.org", member_origin);

            THEN("the response wraps the PDU with the local origin")
            {
                REQUIRE(result.status == RoomReadStatus::ok);
                REQUIRE(result.body.find("local.example.org") != std::string::npos);
                REQUIRE(result.body.find("m.room.message") != std::string::npos);
                REQUIRE(result.body.find("pdus") != std::string::npos);
            }
        }

        WHEN("an unknown event id is queried")
        {
            auto const result = merovingian::federation::build_event_response(store, "$nonexistent:remote.example.org",
                                                                              "local.example.org", member_origin);

            THEN("the event is reported as not found")
            {
                REQUIRE(result.status == RoomReadStatus::not_found);
                REQUIRE(result.body.empty());
            }
        }
    }
}

SCENARIO("Federation event response refuses a server that is not in the event's room",
         "[federation][events][query][fed2][security]")
{
    GIVEN("a room whose only joined user belongs to another server")
    {
        auto store = store_with_room_events();

        WHEN("a server with no user in the room asks for one of its events")
        {
            auto const result = merovingian::federation::build_event_response(store, "$message:remote.example.org",
                                                                              "local.example.org", stranger_origin);

            THEN("the answer is forbidden and carries no room data")
            {
                REQUIRE(result.status == RoomReadStatus::forbidden);
                REQUIRE(result.body.empty());
            }
        }

        AND_WHEN("the stranger's user only has an invite, has left, or is banned")
        {
            set_membership(store, "@invited:stranger.example.org", "invite");
            set_membership(store, "@left:stranger.example.org", "leave");
            set_membership(store, "@banned:stranger.example.org", "ban");
            auto const result = merovingian::federation::build_event_response(store, "$message:remote.example.org",
                                                                              "local.example.org", stranger_origin);

            THEN("it is still forbidden, because only a join counts")
            {
                REQUIRE(result.status == RoomReadStatus::forbidden);
                REQUIRE(result.body.empty());
            }
        }

        AND_WHEN("a user of the stranger server is joined")
        {
            set_membership(store, "@bob:stranger.example.org", "join");
            auto const result = merovingian::federation::build_event_response(store, "$message:remote.example.org",
                                                                              "local.example.org", stranger_origin);

            THEN("the server can read the event")
            {
                REQUIRE(result.status == RoomReadStatus::ok);
                REQUIRE(result.body.find("m.room.message") != std::string::npos);
            }
        }

        AND_WHEN("the room becomes world readable")
        {
            set_history_visibility(store, "world_readable");
            auto const result = merovingian::federation::build_event_response(store, "$message:remote.example.org",
                                                                              "local.example.org", stranger_origin);

            THEN("a server with no user in the room can read the event")
            {
                REQUIRE(result.status == RoomReadStatus::ok);
            }
        }

        AND_WHEN("the room's history visibility is anything other than world_readable")
        {
            set_history_visibility(store, "shared");
            auto const result = merovingian::federation::build_event_response(store, "$message:remote.example.org",
                                                                              "local.example.org", stranger_origin);

            THEN("it stays forbidden")
            {
                REQUIRE(result.status == RoomReadStatus::forbidden);
            }
        }

        AND_WHEN("the stranger asks for an event that does not exist")
        {
            auto const result = merovingian::federation::build_event_response(store, "$nonexistent:remote.example.org",
                                                                              "local.example.org", stranger_origin);

            THEN("the answer is not found rather than forbidden")
            {
                REQUIRE(result.status == RoomReadStatus::not_found);
            }
        }
    }
}

SCENARIO("A server-name suffix or port does not make a server a member of the room",
         "[federation][events][query][fed2][security]")
{
    GIVEN("a room with one joined user on remote.example.org")
    {
        auto const store = store_with_room_events();

        WHEN("the requester is a look-alike server name")
        {
            THEN("origin_may_read_room refuses each look-alike")
            {
                REQUIRE_FALSE(merovingian::federation::origin_may_read_room(store, room_id_under_test,
                                                                            "evil-remote.example.org"));
                REQUIRE_FALSE(merovingian::federation::origin_may_read_room(store, room_id_under_test,
                                                                            "remote.example.org.evil.example"));
                REQUIRE_FALSE(merovingian::federation::origin_may_read_room(store, room_id_under_test, ""));
                REQUIRE_FALSE(merovingian::federation::origin_may_read_room(store, room_id_under_test,
                                                                            "remote.example.org:8448"));
            }
        }

        WHEN("the requester is the joined user's own server")
        {
            THEN("origin_may_read_room allows it")
            {
                REQUIRE(merovingian::federation::origin_may_read_room(store, room_id_under_test, member_origin));
            }
        }

        WHEN("the room is unknown")
        {
            THEN("origin_may_read_room refuses everyone")
            {
                REQUIRE_FALSE(
                    merovingian::federation::origin_may_read_room(store, "!nowhere:remote.example.org", member_origin));
            }
        }
    }

    GIVEN("a room whose joined user's server name carries a port")
    {
        auto store = merovingian::database::PersistentStore{};
        store.events.push_back({"$m",
                                std::string{room_id_under_test},
                                "@carol:ported.example.org:8448",
                                R"({"type":"m.room.member","state_key":"@carol:ported.example.org:8448",)"
                                R"("content":{"membership":"join"}})",
                                1U,
                                1U,
                                {},
                                {},
                                {}});
        store.state.push_back(
            {std::string{room_id_under_test}, "m.room.member", "@carol:ported.example.org:8448", "$m"});

        WHEN("the requester names that server with its port")
        {
            THEN("it is a member, and the bare hostname is not")
            {
                REQUIRE(merovingian::federation::origin_may_read_room(store, room_id_under_test,
                                                                      "ported.example.org:8448"));
                REQUIRE_FALSE(
                    merovingian::federation::origin_may_read_room(store, room_id_under_test, "ported.example.org"));
                REQUIRE_FALSE(merovingian::federation::origin_may_read_room(store, room_id_under_test, "8448"));
            }
        }
    }
}

SCENARIO("Federation state response returns the room's state as of the requested event",
         "[federation][events][state][fed2]")
{
    GIVEN("a store with state events for a room and a joined user from the requesting server")
    {
        auto const store = store_with_room_events();

        WHEN("the state is queried at an event of that room")
        {
            auto const result = merovingian::federation::build_state_response(
                store, room_id_under_test, "$message:remote.example.org", member_origin);

            THEN("the response carries the state PDUs and an auth_chain")
            {
                REQUIRE(result.status == RoomReadStatus::ok);
                REQUIRE(result.body.find("m.room.create") != std::string::npos);
                REQUIRE(result.body.find("m.room.member") != std::string::npos);
                REQUIRE(result.body.find("auth_chain") != std::string::npos);
            }
        }

        WHEN("the state is queried at an event ID this server has never stored")
        {
            auto const result = merovingian::federation::build_state_response(
                store, room_id_under_test, "$unknown:remote.example.org", member_origin);

            THEN("the answer is not found and does not fall back to the current state")
            {
                REQUIRE(result.status == RoomReadStatus::not_found);
                REQUIRE(result.body.empty());
            }
        }

        WHEN("the state is queried at an event that belongs to a different room")
        {
            auto const result = merovingian::federation::build_state_response(
                store, room_id_under_test, "$elsewhere:remote.example.org", member_origin);

            THEN("the answer is not found")
            {
                REQUIRE(result.status == RoomReadStatus::not_found);
                REQUIRE(result.body.empty());
            }
        }

        WHEN("state is queried for an unknown room by a server that is not in it")
        {
            auto const result = merovingian::federation::build_state_response(
                store, "!unknown:remote.example.org", "$message:remote.example.org", member_origin);

            THEN("the answer is forbidden, so room existence is not revealed")
            {
                REQUIRE(result.status == RoomReadStatus::forbidden);
                REQUIRE(result.body.empty());
            }
        }
    }
}

SCENARIO("Federation state response refuses a server that is not in the room",
         "[federation][events][state][fed2][security]")
{
    GIVEN("a room whose only joined user belongs to another server")
    {
        auto store = store_with_room_events();

        WHEN("a server with no user in the room asks for the state")
        {
            auto const result = merovingian::federation::build_state_response(
                store, room_id_under_test, "$message:remote.example.org", stranger_origin);

            THEN("the answer is forbidden and carries no state, members or auth chain")
            {
                REQUIRE(result.status == RoomReadStatus::forbidden);
                REQUIRE(result.body.empty());
            }
        }

        AND_WHEN("the stranger asks with an event ID that does not exist")
        {
            auto const result = merovingian::federation::build_state_response(
                store, room_id_under_test, "$unknown:remote.example.org", stranger_origin);

            THEN("it is still forbidden, so membership is checked before the event is looked up")
            {
                REQUIRE(result.status == RoomReadStatus::forbidden);
            }
        }

        AND_WHEN("the room is world readable")
        {
            set_history_visibility(store, "world_readable");
            auto const result = merovingian::federation::build_state_response(
                store, room_id_under_test, "$message:remote.example.org", stranger_origin);

            THEN("the stranger can read the state")
            {
                REQUIRE(result.status == RoomReadStatus::ok);
                REQUIRE(result.body.find("m.room.create") != std::string::npos);
            }
        }
    }
}

SCENARIO("Federation state_ids response returns event IDs only, to servers in the room",
         "[federation][events][state-ids][fed2]")
{
    GIVEN("a store with state events for a room")
    {
        auto store = store_with_room_events();

        WHEN("a server with a joined user asks for state_ids at an event of the room")
        {
            auto const result = merovingian::federation::build_state_ids_response(
                store, room_id_under_test, "$message:remote.example.org", member_origin);

            THEN("the response carries pdu_ids and auth_chain_ids without event bodies")
            {
                REQUIRE(result.status == RoomReadStatus::ok);
                REQUIRE(result.body.find("$create:remote.example.org") != std::string::npos);
                REQUIRE(result.body.find("$member:remote.example.org") != std::string::npos);
                REQUIRE(result.body.find("pdu_ids") != std::string::npos);
                // The event bodies must not appear in a state_ids response.
                REQUIRE(result.body.find("m.room.create") == std::string::npos);
            }
        }

        WHEN("a server with a joined user asks for state_ids at an unknown event ID")
        {
            auto const result = merovingian::federation::build_state_ids_response(
                store, room_id_under_test, "$unknown:remote.example.org", member_origin);

            THEN("the answer is not found and the current state is not substituted")
            {
                REQUIRE(result.status == RoomReadStatus::not_found);
                REQUIRE(result.body.empty());
            }
        }

        WHEN("a server with no user in the room asks for state_ids")
        {
            auto const result = merovingian::federation::build_state_ids_response(
                store, room_id_under_test, "$message:remote.example.org", stranger_origin);

            THEN("the answer is forbidden and carries no event IDs")
            {
                REQUIRE(result.status == RoomReadStatus::forbidden);
                REQUIRE(result.body.empty());
            }
        }

        WHEN("the room is world readable and a server with no user in the room asks for state_ids")
        {
            set_history_visibility(store, "world_readable");
            auto const result = merovingian::federation::build_state_ids_response(
                store, room_id_under_test, "$message:remote.example.org", stranger_origin);

            THEN("the answer is ok")
            {
                REQUIRE(result.status == RoomReadStatus::ok);
                REQUIRE(result.body.find("pdu_ids") != std::string::npos);
            }
        }
    }
}

SCENARIO("Federation backfill refuses a server that is not in the room",
         "[federation][events][backfill][fed2][security]")
{
    GIVEN("a room whose only joined user belongs to another server")
    {
        auto store = store_with_room_events();
        auto request = merovingian::federation::BackfillRequest{};
        request.room_id = std::string{room_id_under_test};
        request.event_ids = {"$message:remote.example.org"};
        request.limit = 10U;

        WHEN("a server with no user in the room backfills")
        {
            request.origin = std::string{stranger_origin};
            auto const result = merovingian::federation::build_backfill_response(store, request);

            THEN("the answer is 403 and carries no PDUs")
            {
                REQUIRE_FALSE(result.accepted);
                REQUIRE(result.status == 403U);
                REQUIRE(result.reason.find("M_FORBIDDEN") != std::string::npos);
                REQUIRE(result.pdus_json.empty());
            }
        }

        WHEN("a server with a joined user backfills")
        {
            request.origin = std::string{member_origin};
            auto const result = merovingian::federation::build_backfill_response(store, request);

            THEN("it receives the requested event and its predecessors")
            {
                REQUIRE(result.accepted);
                REQUIRE(result.pdus_json.size() == 3U);
            }
        }

        WHEN("the request carries no origin at all")
        {
            auto const result = merovingian::federation::build_backfill_response(store, request);

            THEN("the request fails closed")
            {
                REQUIRE_FALSE(result.accepted);
                REQUIRE(result.status == 403U);
            }
        }

        WHEN("the room is world readable and a server with no user in the room backfills")
        {
            set_history_visibility(store, "world_readable");
            request.origin = std::string{stranger_origin};
            auto const result = merovingian::federation::build_backfill_response(store, request);

            THEN("the request is served")
            {
                REQUIRE(result.accepted);
                REQUIRE_FALSE(result.pdus_json.empty());
            }
        }
    }
}

// Spec: SS API v1.19, POST /_matrix/federation/v1/get_missing_events/{roomId}:
// "a breadth-first walk of the `prev_events` for the `latest_events`, ignoring any
// events in `earliest_events` and stopping at the `limit`"; the 200 response is
// "The previous events for `latest_events`, excluding any `earliest_events`, up to
// the provided `limit`". `limit` defaults to 10 and `min_depth` to 0.
SCENARIO("Federation get_missing_events walks back from latest_events and stops at earliest_events",
         "[federation][events][missing][fed2]")
{
    GIVEN("a store with a linear room event graph and a joined user from the requesting server")
    {
        auto const store = store_with_room_events();

        WHEN("the walk starts at the message and nothing is excluded")
        {
            auto const result = merovingian::federation::build_get_missing_events_response(
                store, room_id_under_test,
                R"({"latest_events":["$message:remote.example.org"],"earliest_events":[],"limit":10})", member_origin);

            THEN("the previous events are returned but not the latest event itself")
            {
                REQUIRE(result.status == RoomReadStatus::ok);
                REQUIRE(result.body.find("m.room.member") != std::string::npos);
                REQUIRE(result.body.find("m.room.create") != std::string::npos);
                REQUIRE(result.body.find("m.room.message") == std::string::npos);
            }
        }

        WHEN("min_depth excludes the create event")
        {
            auto const result = merovingian::federation::build_get_missing_events_response(
                store, room_id_under_test,
                R"({"latest_events":["$message:remote.example.org"],"earliest_events":[],"min_depth":2,"limit":10})",
                member_origin);

            THEN("only previous events with depth >= min_depth are returned")
            {
                REQUIRE(result.status == RoomReadStatus::ok);
                REQUIRE(result.body.find("m.room.member") != std::string::npos);
                REQUIRE(result.body.find("m.room.create") == std::string::npos);
            }
        }

        WHEN("limit is lower than the number of previous events")
        {
            auto const result = merovingian::federation::build_get_missing_events_response(
                store, room_id_under_test,
                R"({"latest_events":["$message:remote.example.org"],"earliest_events":[],"limit":1})", member_origin);

            THEN("the breadth-first walk returns only the nearest previous event")
            {
                REQUIRE(result.status == RoomReadStatus::ok);
                REQUIRE(result.body.find("m.room.member") != std::string::npos);
                REQUIRE(result.body.find("m.room.create") == std::string::npos);
            }
        }

        WHEN("the member event is listed in earliest_events")
        {
            auto const result = merovingian::federation::build_get_missing_events_response(
                store, room_id_under_test,
                R"({"latest_events":["$message:remote.example.org"],"earliest_events":["$member:remote.example.org"],"limit":10})",
                member_origin);

            THEN("neither it nor anything behind it is returned")
            {
                REQUIRE(result.status == RoomReadStatus::ok);
                REQUIRE(result.body.find("m.room.member") == std::string::npos);
                REQUIRE(result.body.find("m.room.create") == std::string::npos);
                REQUIRE(result.body.find("m.room.message") == std::string::npos);
            }
        }

        WHEN("a latest event belongs to a different room")
        {
            auto const result = merovingian::federation::build_get_missing_events_response(
                store, room_id_under_test,
                R"({"latest_events":["$elsewhere:remote.example.org"],"earliest_events":[],"limit":10})",
                member_origin);

            THEN("nothing from the other room is returned")
            {
                REQUIRE(result.status == RoomReadStatus::ok);
                REQUIRE(result.body.find("other") == std::string::npos);
            }
        }
    }
}

SCENARIO("Federation get_missing_events never returns more than the server-side cap",
         "[federation][events][missing][fed2][security]")
{
    GIVEN("a room with a chain of 40 events and a joined user from the requesting server")
    {
        auto const store = store_with_chain(40U);
        auto const latest = std::string{R"("latest_events":["$c39"])"};

        WHEN("the request asks for a limit of 1000")
        {
            auto const result = merovingian::federation::build_get_missing_events_response(
                store, room_id_under_test, "{" + latest + R"(,"earliest_events":[],"limit":1000})", member_origin);

            THEN("at most 20 events come back, the nearest ones, never the latest itself")
            {
                REQUIRE(result.status == RoomReadStatus::ok);
                REQUIRE(count_occurrences(result.body, "m.room.message") == 20U);
                REQUIRE(result.body.find(R"("body":"c38")") != std::string::npos);
                REQUIRE(result.body.find(R"("body":"c19")") != std::string::npos);
                REQUIRE(result.body.find(R"("body":"c18")") == std::string::npos);
                REQUIRE(result.body.find(R"("body":"c39")") == std::string::npos);
            }
        }

        WHEN("the request omits limit")
        {
            auto const result = merovingian::federation::build_get_missing_events_response(
                store, room_id_under_test, "{" + latest + R"(,"earliest_events":[]})", member_origin);

            THEN("the spec default of 10 applies")
            {
                REQUIRE(result.status == RoomReadStatus::ok);
                REQUIRE(count_occurrences(result.body, "m.room.message") == 10U);
            }
        }

        WHEN("the request asks for a limit of zero or less")
        {
            auto const zero = merovingian::federation::build_get_missing_events_response(
                store, room_id_under_test, "{" + latest + R"(,"earliest_events":[],"limit":0})", member_origin);
            auto const negative = merovingian::federation::build_get_missing_events_response(
                store, room_id_under_test, "{" + latest + R"(,"earliest_events":[],"limit":-5})", member_origin);

            THEN("no events are returned")
            {
                REQUIRE(zero.status == RoomReadStatus::ok);
                REQUIRE(count_occurrences(zero.body, "m.room.message") == 0U);
                REQUIRE(negative.status == RoomReadStatus::ok);
                REQUIRE(count_occurrences(negative.body, "m.room.message") == 0U);
            }
        }

        WHEN("earliest_events names $c30 and the limit is 1000")
        {
            auto const result = merovingian::federation::build_get_missing_events_response(
                store, room_id_under_test, "{" + latest + R"(,"earliest_events":["$c30"],"limit":1000})",
                member_origin);

            THEN("exactly the events strictly between $c30 and $c39 come back, none at or behind $c30")
            {
                REQUIRE(result.status == RoomReadStatus::ok);
                REQUIRE(count_occurrences(result.body, "m.room.message") == 8U);
                REQUIRE(result.body.find(R"("body":"c31")") != std::string::npos);
                REQUIRE(result.body.find(R"("body":"c38")") != std::string::npos);
                REQUIRE(result.body.find(R"("body":"c30")") == std::string::npos);
                REQUIRE(result.body.find(R"("body":"c29")") == std::string::npos);
            }
        }

        WHEN("min_depth sits in the middle of the chain")
        {
            auto const result = merovingian::federation::build_get_missing_events_response(
                store, room_id_under_test, "{" + latest + R"(,"earliest_events":[],"limit":1000,"min_depth":1035})",
                member_origin);

            THEN("events below min_depth are neither returned nor walked past")
            {
                REQUIRE(result.status == RoomReadStatus::ok);
                REQUIRE(count_occurrences(result.body, "m.room.message") == 4U);
                REQUIRE(result.body.find(R"("body":"c35")") != std::string::npos);
                REQUIRE(result.body.find(R"("body":"c34")") == std::string::npos);
            }
        }

        WHEN("the request lists an absurd number of latest_events")
        {
            auto body = std::string{R"({"earliest_events":[],"limit":10,"latest_events":[)"};
            for (auto i = 0; i < 1000; ++i)
            {
                body += (i == 0 ? "" : ",");
                body += "\"$bogus" + std::to_string(i) + "\"";
            }
            body += "]}";
            auto const result = merovingian::federation::build_get_missing_events_response(store, room_id_under_test,
                                                                                           body, member_origin);

            THEN("the request is rejected instead of walking the store once per entry")
            {
                REQUIRE(result.status == RoomReadStatus::malformed);
            }
        }
    }
}

SCENARIO("Federation get_missing_events rejects unusable bodies", "[federation][events][missing][fed2]")
{
    GIVEN("a store and a server that is in the room")
    {
        auto const store = store_with_room_events();

        WHEN("the request body is not JSON")
        {
            auto const result = merovingian::federation::build_get_missing_events_response(store, room_id_under_test,
                                                                                           "not json", member_origin);

            THEN("the request is malformed")
            {
                REQUIRE(result.status == RoomReadStatus::malformed);
                REQUIRE(result.body.empty());
            }
        }

        WHEN("latest_events is missing or is not a list of strings")
        {
            auto const missing = merovingian::federation::build_get_missing_events_response(
                store, room_id_under_test, R"({"earliest_events":[],"limit":5})", member_origin);
            auto const wrong_type = merovingian::federation::build_get_missing_events_response(
                store, room_id_under_test, R"({"earliest_events":[],"latest_events":[1,2]})", member_origin);

            THEN("both are malformed")
            {
                REQUIRE(missing.status == RoomReadStatus::malformed);
                REQUIRE(wrong_type.status == RoomReadStatus::malformed);
            }
        }

        WHEN("earliest_events is missing or limit is not an integer")
        {
            auto const missing = merovingian::federation::build_get_missing_events_response(
                store, room_id_under_test, R"({"latest_events":["$message:remote.example.org"]})", member_origin);
            auto const bad_limit = merovingian::federation::build_get_missing_events_response(
                store, room_id_under_test,
                R"({"latest_events":["$message:remote.example.org"],"earliest_events":[],"limit":"many"})",
                member_origin);

            THEN("both are malformed")
            {
                REQUIRE(missing.status == RoomReadStatus::malformed);
                REQUIRE(bad_limit.status == RoomReadStatus::malformed);
            }
        }
    }
}

SCENARIO("Federation get_missing_events refuses a server that is not in the room",
         "[federation][events][missing][fed2][security]")
{
    GIVEN("a room with events and only a joined user from another server")
    {
        auto store = store_with_room_events();
        auto const body =
            std::string{R"({"latest_events":["$message:remote.example.org"],"earliest_events":[],"limit":10})"};

        WHEN("a server with no user in the room asks for missing events")
        {
            auto const result = merovingian::federation::build_get_missing_events_response(store, room_id_under_test,
                                                                                           body, stranger_origin);

            THEN("the answer is forbidden and carries no events")
            {
                REQUIRE(result.status == RoomReadStatus::forbidden);
                REQUIRE(result.body.empty());
            }
        }

        AND_WHEN("the stranger also sends a malformed body")
        {
            auto const result = merovingian::federation::build_get_missing_events_response(store, room_id_under_test,
                                                                                           "not json", stranger_origin);

            THEN("it is still forbidden: the body is not inspected before the membership check")
            {
                REQUIRE(result.status == RoomReadStatus::forbidden);
            }
        }

        AND_WHEN("the room is world readable")
        {
            set_history_visibility(store, "world_readable");
            auto const result = merovingian::federation::build_get_missing_events_response(store, room_id_under_test,
                                                                                           body, stranger_origin);

            THEN("the stranger is served")
            {
                REQUIRE(result.status == RoomReadStatus::ok);
                REQUIRE(result.body.find("m.room.member") != std::string::npos);
            }
        }
    }
}

SCENARIO("Federation backfill returns requested events and predecessors", "[federation][events][backfill]")
{
    GIVEN("a store with a linear room event graph")
    {
        auto const store = store_with_room_events();

        WHEN("backfill starts from the latest message event")
        {
            auto const pdus = merovingian::federation::build_backfill_pdus(store, "!room:remote.example.org",
                                                                           {"$message:remote.example.org"}, 10U);

            THEN("the requested event and preceding events are returned in graph walk order")
            {
                REQUIRE(pdus.size() == 3U);
                REQUIRE(pdus.at(0).find("m.room.message") != std::string::npos);
                REQUIRE(pdus.at(1).find("m.room.member") != std::string::npos);
                REQUIRE(pdus.at(2).find("m.room.create") != std::string::npos);
            }
        }

        WHEN("the backfill limit is lower than the available predecessor chain")
        {
            auto const pdus = merovingian::federation::build_backfill_pdus(store, "!room:remote.example.org",
                                                                           {"$message:remote.example.org"}, 2U);

            THEN("the response is capped without crossing into other rooms")
            {
                REQUIRE(pdus.size() == 2U);
                REQUIRE(pdus.at(0).find("m.room.message") != std::string::npos);
                REQUIRE(pdus.at(1).find("m.room.member") != std::string::npos);
                REQUIRE(pdus.at(0).find("other") == std::string::npos);
                REQUIRE(pdus.at(1).find("other") == std::string::npos);
            }
        }
    }
}
