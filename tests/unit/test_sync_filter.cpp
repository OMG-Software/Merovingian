// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/sync/sync_filter.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

SCENARIO("Sync filter parser accepts JSON filters and tolerates filter ids", "[sync][filter]")
{
    GIVEN("an inline JSON filter selecting specific room types and senders")
    {
        auto const json = std::string{
            R"({"room":{"timeline":{"types":["m.room.message"],"not_senders":["@bot:example.org"],"limit":3},)"
            R"("rooms":["!keep:example.org"],"include_leave":true},)"
            R"("presence":{"senders":["@alice:example.org"]},)"
            R"("account_data":{"types":["m.tag"]}})"};

        WHEN("the filter is parsed")
        {
            auto const filter = merovingian::sync::parse_filter_argument(json);

            THEN("each nested structure is populated and present is true")
            {
                REQUIRE(filter.present);
                REQUIRE(filter.room.timeline.types == std::vector<std::string>{"m.room.message"});
                REQUIRE(filter.room.timeline.not_senders == std::vector<std::string>{"@bot:example.org"});
                REQUIRE(filter.room.timeline.limit == 3U);
                REQUIRE(filter.room.rooms == std::vector<std::string>{"!keep:example.org"});
                REQUIRE(filter.room.include_leave);
                REQUIRE(filter.presence.senders == std::vector<std::string>{"@alice:example.org"});
                REQUIRE(filter.account_data.types == std::vector<std::string>{"m.tag"});
            }
        }
    }

    GIVEN("a non-JSON filter argument (presumably a filter id)")
    {
        WHEN("the filter is parsed")
        {
            auto const filter = merovingian::sync::parse_filter_argument("0");

            THEN("the result is non-present so the handler falls back to defaults")
            {
                REQUIRE_FALSE(filter.present);
                REQUIRE(filter.room.rooms.empty());
                REQUIRE(filter.room.timeline.types.empty());
            }
        }
    }

    GIVEN("an empty filter argument")
    {
        WHEN("the filter is parsed")
        {
            auto const filter = merovingian::sync::parse_filter_argument("");

            THEN("the result is non-present")
            {
                REQUIRE_FALSE(filter.present);
            }
        }
    }
}

SCENARIO("Event passes filter respects include and exclude lists for types and senders", "[sync][filter]")
{
    GIVEN("a filter with types=[m.room.message] and not_senders=[@bot:example.org]")
    {
        auto filter = merovingian::sync::EventTypeFilter{};
        filter.types = {"m.room.message"};
        filter.not_senders = {"@bot:example.org"};

        WHEN("events with different types and senders are checked")
        {
            auto const allowed = merovingian::sync::event_passes_filter(filter, "m.room.message", "@alice:example.org");
            auto const wrong_type = merovingian::sync::event_passes_filter(filter, "m.room.member", "@alice:example.org");
            auto const blocked_sender = merovingian::sync::event_passes_filter(filter, "m.room.message",
                                                                                 "@bot:example.org");
            auto const empty_filter_match =
                merovingian::sync::event_passes_filter(merovingian::sync::EventTypeFilter{}, "anything", "anyone");

            THEN("only events matching both the type and sender rules are kept")
            {
                REQUIRE(allowed);
                REQUIRE_FALSE(wrong_type);
                REQUIRE_FALSE(blocked_sender);
                REQUIRE(empty_filter_match);
            }
        }
    }
}

SCENARIO("Room passes filter honours include and exclude room lists", "[sync][filter][room]")
{
    GIVEN("a room filter with rooms=[!keep] and not_rooms=[!drop]")
    {
        auto filter = merovingian::sync::RoomFilter{};
        filter.rooms = {"!keep:example.org"};
        filter.not_rooms = {"!drop:example.org"};

        WHEN("rooms are checked")
        {
            auto const kept = merovingian::sync::room_passes_filter(filter, "!keep:example.org");
            auto const not_included = merovingian::sync::room_passes_filter(filter, "!other:example.org");
            auto const dropped = merovingian::sync::room_passes_filter(filter, "!drop:example.org");

            THEN("only rooms in the include list and absent from the exclude list pass")
            {
                REQUIRE(kept);
                REQUIRE_FALSE(not_included);
                REQUIRE_FALSE(dropped);
            }
        }
    }
}
