// SPDX-License-Identifier: GPL-3.0-or-later
//
// PreparedRoomEventFilter: a RoomEventFilter's lists prepared once per request, so that POST /search judging
// every event of every room the user has been in does not pay for the length of lists the client sized
// (security audit run 2, F-30; ADR-0332).
// Spec: Matrix CS API v1.19 § Filtering, RoomEventFilter
// URL:  ../../docs/matrix-v1.19-spec/client-server-api.md#filtering
// `rooms`/`not_rooms` and `senders`/`not_senders` list IDs to include and exclude; `types`/`not_types` list
// event types, where `*` stands for a wildcard, and "A matching type will be excluded even if it is listed
// in the `types` filter". The spec sets no maximum length for any list.

#include "merovingian/sync/PreparedRoomEventFilter.hpp"
#include "merovingian/sync/RoomFilter.hpp"
#include "merovingian/sync/SyncFilter.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <initializer_list>
#include <string>
#include <string_view>
#include <vector>

namespace
{

using merovingian::sync::PreparedRoomEventFilter;
using merovingian::sync::RoomFilter;

[[nodiscard]] auto list_of(std::initializer_list<std::string_view> entries) -> std::vector<std::string>
{
    auto out = std::vector<std::string>{};
    for (auto const entry : entries)
    {
        out.emplace_back(entry);
    }
    return out;
}

} // namespace

SCENARIO("a prepared filter answers as the scanning functions do", "[sync][filter][search]")
{
    GIVEN("filters with each list set, alone and together")
    {
        auto filters = std::vector<RoomFilter>{};
        filters.emplace_back();
        {
            auto filter = RoomFilter{};
            filter.rooms = list_of({"!a:x", "!b:x"});
            filters.push_back(filter);
        }
        {
            auto filter = RoomFilter{};
            filter.not_rooms = list_of({"!a:x"});
            filters.push_back(filter);
        }
        {
            auto filter = RoomFilter{};
            filter.rooms = list_of({"!a:x", "!b:x"});
            filter.not_rooms = list_of({"!b:x"});
            filters.push_back(filter);
        }
        {
            auto filter = RoomFilter{};
            filter.timeline.types = list_of({"m.room.message", "m.room.*"});
            filters.push_back(filter);
        }
        {
            auto filter = RoomFilter{};
            filter.timeline.types = list_of({"m.room.*"});
            filter.timeline.not_types = list_of({"m.room.message", "m.room.name"});
            filters.push_back(filter);
        }
        {
            auto filter = RoomFilter{};
            filter.timeline.types = list_of({"*"});
            filter.timeline.not_types = list_of({"m.*", "org.example.thing"});
            filters.push_back(filter);
        }
        {
            auto filter = RoomFilter{};
            filter.timeline.types = list_of({"m.room.m*", "m.room.message*", "m.room.me*", "m.roo*", "other"});
            filters.push_back(filter);
        }
        {
            auto filter = RoomFilter{};
            filter.timeline.senders = list_of({"@a:x", "@b:x"});
            filter.timeline.not_senders = list_of({"@b:x", "@c:x"});
            filters.push_back(filter);
        }
        {
            auto filter = RoomFilter{};
            filter.rooms = list_of({"!a:x"});
            filter.timeline.types = list_of({"m.room.message"});
            filter.timeline.senders = list_of({"@a:x"});
            filters.push_back(filter);
        }

        auto const rooms = std::vector<std::string_view>{"!a:x", "!b:x", "!c:x", ""};
        auto const types = std::vector<std::string_view>{
            "",      "m.room.message", "m.room.name",       "m.room", "m.room.", "m.room.m",
            "m.roo", "m.reaction",     "org.example.thing", "other",  "othe",    "otherx"};
        auto const senders = std::vector<std::string_view>{"@a:x", "@b:x", "@c:x", "@d:x", ""};

        WHEN("every room, type and sender is judged by both the prepared filter and the scanning functions")
        {
            auto room_mismatches = std::size_t{0U};
            auto event_mismatches = std::size_t{0U};
            for (auto const& filter : filters)
            {
                auto const prepared = PreparedRoomEventFilter{filter};
                for (auto const room : rooms)
                {
                    if (prepared.room_passes(room) != merovingian::sync::room_passes_filter(filter, room))
                    {
                        ++room_mismatches;
                    }
                }
                for (auto const type : types)
                {
                    for (auto const sender : senders)
                    {
                        if (prepared.event_passes(type, sender) !=
                            merovingian::sync::event_passes_filter(filter.timeline, type, sender))
                        {
                            ++event_mismatches;
                        }
                    }
                }
            }

            THEN("they never disagree")
            {
                REQUIRE(room_mismatches == 0U);
                REQUIRE(event_mismatches == 0U);
            }
        }
    }
}

SCENARIO("a filter with very long lists judges as the short list it repeats", "[sync][filter][search][security]")
{
    GIVEN("lists of 100000 entries, most of them repeats or covered by a shorter pattern")
    {
        auto filter = RoomFilter{};
        for (auto i = std::size_t{0U}; i < 100000U; ++i)
        {
            filter.not_rooms.push_back("!excluded" + std::to_string(i % 50U) + ":x");
            filter.timeline.not_senders.push_back("@blocked" + std::to_string(i % 50U) + ":x");
            filter.timeline.not_types.push_back("org.example." + std::to_string(i % 50U) + ".*");
            filter.timeline.types.push_back("m.room." + std::to_string(i) + ".*");
        }
        filter.timeline.types.emplace_back("m.room.*");
        auto const prepared = PreparedRoomEventFilter{filter};

        WHEN("rooms, senders and types are judged")
        {
            THEN("each is judged by the entries it names, however many entries repeat")
            {
                REQUIRE(prepared.room_passes("!kept:x"));
                REQUIRE_FALSE(prepared.room_passes("!excluded7:x"));
                REQUIRE(prepared.event_passes("m.room.message", "@alice:x"));
                REQUIRE_FALSE(prepared.event_passes("m.room.message", "@blocked3:x"));
                REQUIRE_FALSE(prepared.event_passes("org.example.4.x", "@alice:x")); // not in `types`
                REQUIRE_FALSE(prepared.event_passes("m.reaction", "@alice:x"));      // not in `types`
            }
        }
    }

    GIVEN("a types list that names a type and a not_types list that covers it")
    {
        auto filter = RoomFilter{};
        filter.timeline.types = list_of({"m.room.message"});
        filter.timeline.not_types = list_of({"m.room.*"});
        auto const prepared = PreparedRoomEventFilter{filter};

        WHEN("the type is judged")
        {
            THEN("the exclusion wins, as the spec says a matching type is excluded even if listed in types")
            {
                REQUIRE_FALSE(prepared.event_passes("m.room.message", "@a:x"));
            }
        }
    }
}
