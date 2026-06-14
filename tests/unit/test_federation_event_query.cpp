// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation/event_query.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

namespace
{

[[nodiscard]] auto store_with_room_events() -> merovingian::database::PersistentStore
{
    auto store = merovingian::database::PersistentStore{};
    auto const room_id = std::string{"!room:remote.example.org"};
    auto const sender = std::string{"@alice:remote.example.org"};
    store.events.push_back(
        {"$create:remote.example.org", room_id, sender, R"({"type":"m.room.create"})", 1U, 1U, {}, {}, {}});
    store.events.push_back({"$member:remote.example.org",
                            room_id,
                            sender,
                            R"({"type":"m.room.member"})",
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

} // namespace

SCENARIO("Federation event response returns a single signed PDU", "[federation][events][query]")
{
    GIVEN("a store containing the requested event")
    {
        auto const store = store_with_room_events();

        WHEN("the event is queried by id")
        {
            auto const body = merovingian::federation::build_event_response(store, "$message:remote.example.org",
                                                                            "local.example.org");

            THEN("the response wraps the PDU with the local origin")
            {
                REQUIRE_FALSE(body.empty());
                REQUIRE(body.find("local.example.org") != std::string::npos);
                REQUIRE(body.find("m.room.message") != std::string::npos);
                REQUIRE(body.find("pdus") != std::string::npos);
            }
        }

        WHEN("an unknown event id is queried")
        {
            auto const body = merovingian::federation::build_event_response(store, "$nonexistent:remote.example.org",
                                                                            "local.example.org");

            THEN("an empty string signals the event was not found")
            {
                REQUIRE(body.empty());
            }
        }
    }
}

SCENARIO("Federation state response returns the room's current state PDUs", "[federation][events][state]")
{
    GIVEN("a store with state events for a room")
    {
        auto const store = store_with_room_events();

        WHEN("the room state is queried")
        {
            auto const body = merovingian::federation::build_state_response(store, "!room:remote.example.org");

            THEN("the response carries the state PDUs and an auth_chain placeholder")
            {
                REQUIRE_FALSE(body.empty());
                REQUIRE(body.find("m.room.create") != std::string::npos);
                REQUIRE(body.find("m.room.member") != std::string::npos);
                REQUIRE(body.find("auth_chain") != std::string::npos);
            }
        }

        WHEN("state is queried for an unknown room")
        {
            auto const body = merovingian::federation::build_state_response(store, "!unknown:remote.example.org");

            THEN("an empty string signals no recorded state")
            {
                REQUIRE(body.empty());
            }
        }
    }
}

SCENARIO("Federation state_ids response returns event IDs only", "[federation][events][state-ids]")
{
    GIVEN("a store with state events for a room")
    {
        auto const store = store_with_room_events();

        WHEN("state_ids are queried")
        {
            auto const body = merovingian::federation::build_state_ids_response(store, "!room:remote.example.org");

            THEN("the response carries pdu_ids and auth_chain_ids without event bodies")
            {
                REQUIRE_FALSE(body.empty());
                REQUIRE(body.find("$create:remote.example.org") != std::string::npos);
                REQUIRE(body.find("$member:remote.example.org") != std::string::npos);
                REQUIRE(body.find("pdu_ids") != std::string::npos);
                // The event bodies must not appear in a state_ids response.
                REQUIRE(body.find("m.room.create") == std::string::npos);
            }
        }
    }
}

SCENARIO("Federation get_missing_events filters by depth and caps by limit", "[federation][events][missing]")
{
    GIVEN("a store with events at varying depths")
    {
        auto const store = store_with_room_events();

        WHEN("min_depth excludes the create event and limit is generous")
        {
            auto const body = merovingian::federation::build_get_missing_events_response(
                store, "!room:remote.example.org",
                R"({"latest_events":["$message:remote.example.org"],"earliest_events":[],"min_depth":2,"limit":10})");

            THEN("only events with depth >= min_depth are returned")
            {
                REQUIRE_FALSE(body.empty());
                REQUIRE(body.find("m.room.member") != std::string::npos);
                REQUIRE(body.find("m.room.message") != std::string::npos);
                REQUIRE(body.find("m.room.create") == std::string::npos);
            }
        }

        WHEN("limit caps the result count below the available events")
        {
            auto const body = merovingian::federation::build_get_missing_events_response(
                store, "!room:remote.example.org",
                R"({"latest_events":["$message:remote.example.org"],"earliest_events":[],"min_depth":0,"limit":1})");

            THEN("only the earliest qualifying event is returned")
            {
                REQUIRE_FALSE(body.empty());
                REQUIRE(body.find("m.room.create") != std::string::npos);
                REQUIRE(body.find("m.room.message") == std::string::npos);
            }
        }

        WHEN("the request body is not JSON")
        {
            auto const body = merovingian::federation::build_get_missing_events_response(
                store, "!room:remote.example.org", "not json");

            THEN("an empty string signals the malformed request")
            {
                REQUIRE(body.empty());
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
