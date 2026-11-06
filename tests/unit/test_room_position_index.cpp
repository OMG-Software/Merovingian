// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// ADR-0521: RoomPositionIndex is a verified cache with its own lock. It answers as a scan would however the room
// list was edited, and a moved-to index starts empty and rebuilds on demand.

#include "merovingian/homeserver/LocalRoom.hpp"
#include "merovingian/homeserver/RoomPositionIndex.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <type_traits>
#include <utility>
#include <vector>

using merovingian::homeserver::LocalRoom;
using merovingian::homeserver::RoomPositionIndex;

namespace
{

[[nodiscard]] auto room_named(std::string id) -> LocalRoom
{
    return LocalRoom{std::move(id), "@creator:example.org", {"@creator:example.org"}, false};
}

} // namespace

SCENARIO("a moved-to RoomPositionIndex starts empty and still answers correctly", "[homeserver][rooms][p9]")
{
    GIVEN("an index that has answered for three rooms")
    {
        auto rooms = std::vector<LocalRoom>{room_named("!one:example.org"), room_named("!two:example.org"),
                                            room_named("!three:example.org")};
        auto index = RoomPositionIndex{};
        REQUIRE(index.find(rooms, "!three:example.org") == 2U);

        WHEN("it is move constructed and the new index is asked")
        {
            auto moved = RoomPositionIndex{std::move(index)};

            THEN("it rebuilds and finds every room, and reports an unknown room as absent")
            {
                REQUIRE(moved.find(rooms, "!one:example.org") == 0U);
                REQUIRE(moved.find(rooms, "!two:example.org") == 1U);
                REQUIRE(moved.find(rooms, "!three:example.org") == 2U);
                REQUIRE_FALSE(moved.find(rooms, "!none:example.org").has_value());
            }
        }

        WHEN("it is move assigned over an index that knew other rooms")
        {
            auto other_rooms = std::vector<LocalRoom>{room_named("!other:example.org")};
            auto target = RoomPositionIndex{};
            REQUIRE(target.find(other_rooms, "!other:example.org") == 0U);
            target = std::move(index);

            THEN("the assigned-to index answers for the new list")
            {
                REQUIRE(target.find(rooms, "!two:example.org") == 1U);
                REQUIRE_FALSE(target.find(rooms, "!other:example.org").has_value());
            }
        }
    }
}

SCENARIO("a stale RoomPositionIndex still returns the right position", "[homeserver][rooms][p9]")
{
    GIVEN("an index that has answered for two rooms")
    {
        auto rooms = std::vector<LocalRoom>{room_named("!one:example.org"), room_named("!two:example.org")};
        auto const index = RoomPositionIndex{};
        REQUIRE(index.find(rooms, "!two:example.org") == 1U);

        WHEN("a room is removed from the front, shifting the rest")
        {
            rooms.erase(rooms.begin());

            THEN("the shifted room is found at its new position and the removed one is gone")
            {
                REQUIRE(index.find(rooms, "!two:example.org") == 0U);
                REQUIRE_FALSE(index.find(rooms, "!one:example.org").has_value());
            }
        }

        WHEN("a room is replaced in place so the row count is unchanged")
        {
            rooms[0] = room_named("!replacement:example.org");

            THEN("the replacement is found by a scan")
            {
                REQUIRE(index.find(rooms, "!replacement:example.org") == 0U);
                REQUIRE(index.find(rooms, "!two:example.org") == 1U);
            }
        }

        WHEN("a room is appended")
        {
            rooms.push_back(room_named("!three:example.org"));

            THEN("the new room is found")
            {
                REQUIRE(index.find(rooms, "!three:example.org") == 2U);
            }
        }
    }
}

SCENARIO("RoomPositionIndex cannot be copied and moves without throwing", "[homeserver][rooms][p9]")
{
    GIVEN("the index type")
    {
        WHEN("its copy and move operations are inspected")
        {
            THEN("copying is refused and both moves are noexcept")
            {
                STATIC_REQUIRE_FALSE(std::is_copy_constructible_v<RoomPositionIndex>);
                STATIC_REQUIRE_FALSE(std::is_copy_assignable_v<RoomPositionIndex>);
                STATIC_REQUIRE(std::is_nothrow_move_constructible_v<RoomPositionIndex>);
                STATIC_REQUIRE(std::is_nothrow_move_assignable_v<RoomPositionIndex>);
            }
        }
    }
}
