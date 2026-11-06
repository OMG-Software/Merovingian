// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// P9 (ADR-0496): `LocalRoom::members` answers "is this user a member" from a hash set kept in step with its ordered
// list, and `find_local_room` answers "which room" from a position index that is verified, never trusted. Both must
// give the answer a scan would, whatever edited the data before the lookup.

#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/LocalDatabase.hpp"
#include "merovingian/homeserver/LocalRoom.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

using merovingian::homeserver::LocalDatabase;
using merovingian::homeserver::LocalRoom;
using merovingian::homeserver::RoomMembers;

namespace
{

[[nodiscard]] auto room_named(std::string id) -> LocalRoom
{
    return LocalRoom{std::move(id), "@creator:example.org", {"@creator:example.org"}, false};
}

} // namespace

SCENARIO("RoomMembers keeps its list and its set in step", "[homeserver][rooms][p9]")
{
    GIVEN("a roster with two members")
    {
        auto members = RoomMembers{"@a:example.org", "@b:example.org"};

        WHEN("a third joins and a member named twice is added again")
        {
            REQUIRE(members.add("@c:example.org"));
            REQUIRE_FALSE(members.add("@a:example.org"));

            THEN("the list keeps joining order without a duplicate, and every member is found")
            {
                REQUIRE(members.values() ==
                        std::vector<std::string>{"@a:example.org", "@b:example.org", "@c:example.org"});
                REQUIRE(members.contains("@a:example.org"));
                REQUIRE(members.contains("@c:example.org"));
                REQUIRE_FALSE(members.contains("@d:example.org"));
            }
        }

        WHEN("the first member leaves")
        {
            REQUIRE(members.remove("@a:example.org"));

            THEN("the list and the lookup both drop them and the order of the rest is kept")
            {
                REQUIRE(members.values() == std::vector<std::string>{"@b:example.org"});
                REQUIRE_FALSE(members.contains("@a:example.org"));
                REQUIRE_FALSE(members.remove("@a:example.org"));
            }
        }

        WHEN("the roster is cleared and one member is added")
        {
            members.clear();
            REQUIRE(members.add("@z:example.org"));

            THEN("only that member is found")
            {
                REQUIRE(members.values() == std::vector<std::string>{"@z:example.org"});
                REQUIRE_FALSE(members.contains("@b:example.org"));
            }
        }

        WHEN("it is read as the vector the appservice module takes")
        {
            std::vector<std::string> const& as_vector = members;

            THEN("it is the same list")
            {
                REQUIRE(as_vector.size() == 2U);
            }
        }
    }
}

SCENARIO("find_local_room answers as a scan would after the room list is edited", "[homeserver][rooms][p9]")
{
    GIVEN("a database with three rooms looked up once")
    {
        auto database = LocalDatabase{};
        database.rooms.push_back(room_named("!one:example.org"));
        database.rooms.push_back(room_named("!two:example.org"));
        database.rooms.push_back(room_named("!three:example.org"));
        REQUIRE(find_local_room(database, "!two:example.org") == &database.rooms[1]);

        WHEN("a room is added")
        {
            database.rooms.push_back(room_named("!four:example.org"));

            THEN("it is found at its place")
            {
                REQUIRE(find_local_room(database, "!four:example.org") == &database.rooms[3]);
            }
        }

        WHEN("a room is erased")
        {
            database.rooms.erase(database.rooms.begin());

            THEN("it is gone and the rest are found at their new places")
            {
                REQUIRE(find_local_room(database, "!one:example.org") == nullptr);
                REQUIRE(find_local_room(database, "!two:example.org") == &database.rooms[0]);
                REQUIRE(find_local_room(database, "!three:example.org") == &database.rooms[1]);
            }
        }

        WHEN("a room is erased and another is added, so the count is the same")
        {
            database.rooms.erase(database.rooms.begin() + 1);
            database.rooms.push_back(room_named("!new:example.org"));

            THEN("the erased room is not found, the added one is, and no other room answers for either")
            {
                REQUIRE(find_local_room(database, "!two:example.org") == nullptr);
                REQUIRE(find_local_room(database, "!new:example.org") == &database.rooms[2]);
                REQUIRE(find_local_room(database, "!three:example.org") == &database.rooms[1]);
            }
        }

        WHEN("a room is renamed in place")
        {
            database.rooms[1].room_id = "!renamed:example.org";

            THEN("the old ID is not found and the new one is")
            {
                REQUIRE(find_local_room(database, "!two:example.org") == nullptr);
                REQUIRE(find_local_room(database, "!renamed:example.org") == &database.rooms[1]);
            }
        }

        WHEN("all rooms are cleared")
        {
            database.rooms.clear();

            THEN("none is found")
            {
                REQUIRE(find_local_room(database, "!one:example.org") == nullptr);
            }
        }

        WHEN("an ID that no room has is looked up through a const database")
        {
            auto const& view = database;

            THEN("the answer is none, and a held ID is found")
            {
                REQUIRE(find_local_room(view, "!absent:example.org") == nullptr);
                REQUIRE(find_local_room(view, "!three:example.org") == &database.rooms[2]);
            }
        }
    }
}
