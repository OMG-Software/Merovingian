// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/database/persistent_store.hpp"
#include "merovingian/sync/room_access.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

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

// Security audit run-1 (sp01.sliding-sync-extension-rooms-unbounded): the receipts and typing
// extensions classified each named room with its own scan of every membership row, under the
// runtime lock. room_access_index answers for all of a user's rooms in one pass, and must give
// exactly room_access_for's answer for every room, including the tie on equal stream orderings.
SCENARIO("Room access index gives room_access_for's answer for every room in one pass",
         "[sync][sliding-sync][security][sp01]")
{
    using merovingian::sync::room_access_for;
    using merovingian::sync::room_access_index;
    using merovingian::sync::RoomAccess;

    GIVEN("a store with several rooms, several users, superseded rows and an equal-ordering tie")
    {
        auto store = merovingian::database::PersistentStore{};
        store.memberships.push_back({"!a:example.org", "@u:example.org", "join", 1U});
        store.memberships.push_back({"!b:example.org", "@u:example.org", "invite", 2U});
        store.memberships.push_back({"!c:example.org", "@u:example.org", "join", 3U});
        store.memberships.push_back({"!c:example.org", "@u:example.org", "leave", 7U});
        store.memberships.push_back({"!d:example.org", "@u:example.org", "ban", 5U});
        store.memberships.push_back({"!d:example.org", "@u:example.org", "join", 4U});
        store.memberships.push_back({"!e:example.org", "@u:example.org", "join", 6U});
        store.memberships.push_back({"!e:example.org", "@u:example.org", "leave", 6U});
        store.memberships.push_back({"!a:example.org", "@other:example.org", "ban", 9U});
        store.memberships.push_back({"!f:example.org", "@other:example.org", "join", 10U});

        WHEN("the index is built for one user")
        {
            auto const index = room_access_index(store, "@u:example.org");
            auto const via_index = [&index](std::string const& room_id) {
                auto const found = index.find(room_id);
                return found == index.end() ? RoomAccess::none : found->second;
            };

            THEN("every room answers as room_access_for does")
            {
                for (auto const* room_id : {"!a:example.org", "!b:example.org", "!c:example.org", "!d:example.org",
                                            "!e:example.org", "!f:example.org", "!unknown:example.org"})
                {
                    CAPTURE(room_id);
                    REQUIRE(via_index(room_id) == room_access_for(store, room_id, "@u:example.org"));
                }
            }

            THEN("another user's rows do not leak into the index")
            {
                REQUIRE(via_index("!f:example.org") == RoomAccess::none);
                REQUIRE(via_index("!a:example.org") == RoomAccess::joined);
            }
        }
    }
}
