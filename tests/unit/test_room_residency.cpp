// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// Unit tests for homeserver::room_state_is_current (ADR-0301): held state is current only when the room's
// create event is held and a user of the local server is joined to it.

#include "merovingian/database/PersistentEvent.hpp"
#include "merovingian/database/PersistentMembership.hpp"
#include "merovingian/database/PersistentStateEvent.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/homeserver/room_residency.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <string_view>

namespace
{

constexpr auto room = std::string_view{"!room:remote.example"};
constexpr auto local = std::string_view{"local.example"};

auto add_create_event(merovingian::database::PersistentStore& store, std::string_view room_id) -> void
{
    auto event = merovingian::database::PersistentEvent{};
    event.event_id = "$create-" + std::string{room_id};
    event.room_id = std::string{room_id};
    event.json = R"({"type":"m.room.create","content":{"room_version":"11"}})";
    store.events.push_back(event);
    store.state.push_back({std::string{room_id}, "m.room.create", "", event.event_id});
}

auto add_membership(merovingian::database::PersistentStore& store, std::string_view room_id, std::string_view user,
                    std::string_view membership) -> void
{
    store.memberships.push_back({std::string{room_id}, std::string{user}, std::string{membership}, 1U});
}

} // namespace

SCENARIO("Held room state is current only with a create event and a joined local user", "[homeserver][room][unit]")
{
    GIVEN("a store holding the room's create event")
    {
        auto store = merovingian::database::PersistentStore{};
        add_create_event(store, room);

        WHEN("only a remote user is a member")
        {
            add_membership(store, room, "@alice:remote.example", "join");

            THEN("the state is not current: no resident sends the room's later events here")
            {
                REQUIRE_FALSE(merovingian::homeserver::room_state_is_current(store, room, local));
            }
        }

        WHEN("a local user has left")
        {
            add_membership(store, room, "@bob:local.example", "leave");

            THEN("the state is not current")
            {
                REQUIRE_FALSE(merovingian::homeserver::room_state_is_current(store, room, local));
            }
        }

        WHEN("a local user is only invited")
        {
            add_membership(store, room, "@bob:local.example", "invite");

            THEN("the state is not current")
            {
                REQUIRE_FALSE(merovingian::homeserver::room_state_is_current(store, room, local));
            }
        }

        WHEN("a local user is joined")
        {
            add_membership(store, room, "@bob:local.example", "join");

            THEN("the state is current")
            {
                REQUIRE(merovingian::homeserver::room_state_is_current(store, room, local));
            }
        }

        WHEN("a user of a server whose name merely ends like ours is joined")
        {
            add_membership(store, room, "@bob:notlocal.example", "join");

            THEN("it does not count as a local user")
            {
                REQUIRE_FALSE(merovingian::homeserver::room_state_is_current(store, room, local));
            }
        }

        WHEN("the local user is joined to a different room only")
        {
            add_membership(store, "!other:remote.example", "@bob:local.example", "join");

            THEN("this room's state is not current")
            {
                REQUIRE_FALSE(merovingian::homeserver::room_state_is_current(store, room, local));
            }
        }
    }

    GIVEN("a store with a local member but no create event")
    {
        auto store = merovingian::database::PersistentStore{};
        add_membership(store, room, "@bob:local.example", "join");

        WHEN("currency is asked")
        {
            THEN("the state is not current")
            {
                REQUIRE_FALSE(merovingian::homeserver::room_state_is_current(store, room, local));
            }
        }
    }
}
