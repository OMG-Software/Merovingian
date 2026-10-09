// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// homeserver::may_send_state_event (CSAZ-12): whether a user may send a state event of a type in a
// room's current state, judged as the authorization rules judge it.

#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/room_power.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <utility>

namespace
{

auto add_state_event(merovingian::database::PersistentStore& store, std::string const& event_id,
                     std::string const& event_type, std::string const& json) -> void
{
    auto event = merovingian::database::PersistentEvent{};
    event.event_id = event_id;
    event.room_id = "!room:example.org";
    event.sender_user_id = "@alice:example.org";
    event.json = json;
    store.events.push_back(std::move(event));
    store.state.push_back({"!room:example.org", event_type, "", event_id});
}

auto add_create(merovingian::database::PersistentStore& store, std::string const& room_version) -> void
{
    add_state_event(store, "$create", "m.room.create",
                    R"({"type":"m.room.create","state_key":"","sender":"@alice:example.org",)"
                    R"("room_id":"!room:example.org","content":{"room_version":")" +
                        room_version + R"(","creator":"@alice:example.org"}})");
}

auto add_power_levels(merovingian::database::PersistentStore& store, std::string const& content) -> void
{
    add_state_event(store, "$power", "m.room.power_levels",
                    R"({"type":"m.room.power_levels","state_key":"","sender":"@alice:example.org",)"
                    R"("room_id":"!room:example.org","content":)" +
                        content + "}");
}

[[nodiscard]] auto may_send(merovingian::database::PersistentStore const& store, std::string const& user,
                            std::string const& event_type) -> bool
{
    return merovingian::homeserver::may_send_state_event(store, "!room:example.org", user, event_type);
}

} // namespace

SCENARIO("may_send_state_event refuses when the room's version cannot be established", "[homeserver][power][csaz-12]")
{
    GIVEN("a store with no create event for the room")
    {
        auto store = merovingian::database::PersistentStore{};

        WHEN("the creator asks to send a state event")
        {
            auto const allowed = may_send(store, "@alice:example.org", "m.room.name");

            THEN("it is refused")
            {
                REQUIRE_FALSE(allowed);
            }
        }
    }
    GIVEN("a room whose create event names an unknown room version")
    {
        auto store = merovingian::database::PersistentStore{};
        add_create(store, "999");

        WHEN("the creator asks to send a state event")
        {
            auto const allowed = may_send(store, "@alice:example.org", "m.room.name");

            THEN("it is refused")
            {
                REQUIRE_FALSE(allowed);
            }
        }
    }
    GIVEN("a room whose create event content has no room_version (room version 1, unsupported)")
    {
        auto store = merovingian::database::PersistentStore{};
        add_state_event(store, "$create", "m.room.create",
                        R"({"type":"m.room.create","state_key":"","sender":"@alice:example.org",)"
                        R"("room_id":"!room:example.org","content":{"creator":"@alice:example.org"}})");

        WHEN("the creator asks to send a state event")
        {
            auto const allowed = may_send(store, "@alice:example.org", "m.room.name");

            THEN("it is refused")
            {
                REQUIRE_FALSE(allowed);
            }
        }
    }
}

SCENARIO("may_send_state_event refuses when the room's create event cannot be read", "[homeserver][power][csaz-12]")
{
    GIVEN("a room whose current create state names an event the store does not hold")
    {
        auto store = merovingian::database::PersistentStore{};
        store.state.push_back({"!room:example.org", "m.room.create", "", "$missing"});

        WHEN("the creator asks to send a state event")
        {
            auto const allowed = may_send(store, "@alice:example.org", "m.room.name");

            THEN("it is refused")
            {
                REQUIRE_FALSE(allowed);
            }
        }
    }
    GIVEN("a room whose create event content is not an object, and one whose create event has no content")
    {
        auto bad_content = merovingian::database::PersistentStore{};
        add_state_event(bad_content, "$create", "m.room.create",
                        R"({"type":"m.room.create","state_key":"","sender":"@alice:example.org","content":"10"})");
        auto no_content = merovingian::database::PersistentStore{};
        add_state_event(no_content, "$create", "m.room.create",
                        R"({"type":"m.room.create","state_key":"","sender":"@alice:example.org"})");

        WHEN("the creator asks to send a state event in each")
        {
            auto const with_bad_content = may_send(bad_content, "@alice:example.org", "m.room.name");
            auto const with_no_content = may_send(no_content, "@alice:example.org", "m.room.name");

            THEN("both are refused")
            {
                REQUIRE_FALSE(with_bad_content);
                REQUIRE_FALSE(with_no_content);
            }
        }
    }
}

SCENARIO("may_send_state_event compares the user's power with the event's required level",
         "[homeserver][power][csaz-12]")
{
    GIVEN("a room version 10 room with no power levels event")
    {
        auto store = merovingian::database::PersistentStore{};
        add_create(store, "10");

        WHEN("the creator (level 100) and another user (level 0) ask to send a state event")
        {
            auto const creator = may_send(store, "@alice:example.org", "m.room.canonical_alias");
            auto const other = may_send(store, "@bob:example.org", "m.room.canonical_alias");

            THEN("only the creator meets the default state level of 50")
            {
                REQUIRE(creator);
                REQUIRE_FALSE(other);
            }
        }
    }
    GIVEN("a room version 10 room where bob has 50, state_default is 50 and tombstones need 100")
    {
        auto store = merovingian::database::PersistentStore{};
        add_create(store, "10");
        add_power_levels(store, R"({"users":{"@alice:example.org":100,"@bob:example.org":50},)"
                                R"("state_default":50,"events":{"m.room.tombstone":100}})");

        WHEN("alice, bob and carol ask to send a canonical alias and a tombstone")
        {
            auto const bob_alias = may_send(store, "@bob:example.org", "m.room.canonical_alias");
            auto const bob_tombstone = may_send(store, "@bob:example.org", "m.room.tombstone");
            auto const alice_tombstone = may_send(store, "@alice:example.org", "m.room.tombstone");
            auto const carol_alias = may_send(store, "@carol:example.org", "m.room.canonical_alias");

            THEN("each is judged against events[type], else state_default")
            {
                REQUIRE(bob_alias);
                REQUIRE_FALSE(bob_tombstone);
                REQUIRE(alice_tombstone);
                REQUIRE_FALSE(carol_alias);
            }
        }
    }
    GIVEN("a room version 12 room whose power levels reserve tombstones for a level above every user")
    {
        auto store = merovingian::database::PersistentStore{};
        add_create(store, "12");
        add_power_levels(store, R"({"users":{"@bob:example.org":100},"events":{"m.room.tombstone":150}})");

        WHEN("the creator and bob ask to send a tombstone")
        {
            auto const creator = may_send(store, "@alice:example.org", "m.room.tombstone");
            auto const bob = may_send(store, "@bob:example.org", "m.room.tombstone");

            THEN("the creator, whose power is infinite from room version 12, may and bob may not")
            {
                REQUIRE(creator);
                REQUIRE_FALSE(bob);
            }
        }
    }
}
