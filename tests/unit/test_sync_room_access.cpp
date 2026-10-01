// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/database/persistent_store.hpp"
#include "merovingian/sync/room_access.hpp"

#include <catch2/catch_test_macros.hpp>

// Spec (C-S API, Room history visibility): "In all cases except world_readable, a user needs
// to join a room to view events in that room." Sliding sync uses this classification to
// decide whether a client-named room may be served at all.
SCENARIO("Room access classifies a user's current membership for sliding sync",
         "[sync][sliding-sync][security][csaz-1]")
{
    using merovingian::sync::room_access_for;
    using merovingian::sync::RoomAccess;

    GIVEN("a store with one membership row per user in a room")
    {
        auto store = merovingian::database::PersistentStore{};
        store.memberships.push_back({"!r:example.org", "@joined:example.org", "join", 1U});
        store.memberships.push_back({"!r:example.org", "@invited:example.org", "invite", 2U});
        store.memberships.push_back({"!r:example.org", "@left:example.org", "leave", 3U});
        store.memberships.push_back({"!r:example.org", "@banned:example.org", "ban", 4U});
        store.memberships.push_back({"!r:example.org", "@knocked:example.org", "knock", 5U});

        WHEN("each user's access to the room is classified")
        {
            THEN("only join is joined and only invite is invited")
            {
                REQUIRE(room_access_for(store, "!r:example.org", "@joined:example.org") == RoomAccess::joined);
                REQUIRE(room_access_for(store, "!r:example.org", "@invited:example.org") == RoomAccess::invited);
            }

            THEN("leave, ban, knock and no membership at all give no access")
            {
                REQUIRE(room_access_for(store, "!r:example.org", "@left:example.org") == RoomAccess::none);
                REQUIRE(room_access_for(store, "!r:example.org", "@banned:example.org") == RoomAccess::none);
                REQUIRE(room_access_for(store, "!r:example.org", "@knocked:example.org") == RoomAccess::none);
                REQUIRE(room_access_for(store, "!r:example.org", "@stranger:example.org") == RoomAccess::none);
            }

            THEN("membership in another room does not carry over")
            {
                REQUIRE(room_access_for(store, "!other:example.org", "@joined:example.org") == RoomAccess::none);
            }
        }
    }

    GIVEN("a user with several membership rows for the same room")
    {
        auto store = merovingian::database::PersistentStore{};
        store.memberships.push_back({"!r:example.org", "@u:example.org", "join", 1U});
        store.memberships.push_back({"!r:example.org", "@u:example.org", "ban", 9U});

        WHEN("the user's access is classified")
        {
            THEN("the row with the highest stream ordering is the current membership")
            {
                REQUIRE(room_access_for(store, "!r:example.org", "@u:example.org") == RoomAccess::none);
            }
        }
    }
}
