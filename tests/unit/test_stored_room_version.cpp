// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/stored_room_version.hpp"

#include <catch2/catch_test_macros.hpp>

#include <optional>
#include <string>

namespace
{

// A store holding one room whose current m.room.create event has `create_json` as its JSON.
[[nodiscard]] auto store_with_create(std::string const& create_json) -> merovingian::database::PersistentStore
{
    auto store = merovingian::database::PersistentStore{};
    store.state.push_back({"!r:example.org", "m.room.create", "", "$create"});
    auto event = merovingian::database::PersistentEvent{};
    event.event_id = "$create";
    event.room_id = "!r:example.org";
    event.json = create_json;
    store.events.push_back(std::move(event));
    return store;
}

} // namespace

// Security audit run-1 (rooms.room-version-resolution-divergent-fallbacks-create-without-room_version):
// a room's version is what its m.room.create declares, and "if the room_version is not specified,
// it is 1" (client-server-api.md, m.room.create: "Defaults to \"1\" if the key does not exist";
// this server refuses v1, ADR-0076). Every component used to derive the
// stored version itself, with defaults of "1", "10" and "12". There is now one accessor, and an
// unreadable or non-string declaration resolves to no supported version, never to a default.
SCENARIO("A room's stored version comes from its create event through one accessor that fails closed",
         "[homeserver][rooms][room-version][security]")
{
    using merovingian::homeserver::stored_room_version;
    using merovingian::homeserver::stored_room_version_policy;

    GIVEN("a create event declaring room version 11")
    {
        auto const store = store_with_create(R"({"type":"m.room.create","content":{"room_version":"11"}})");

        WHEN("the stored version is resolved")
        {
            THEN("the version is 11 and its policy is found")
            {
                REQUIRE(stored_room_version(store, "!r:example.org") == std::optional<std::string>{"11"});
                REQUIRE(stored_room_version_policy(store, "!r:example.org") != nullptr);
            }
        }
    }

    GIVEN("a create event with no room_version")
    {
        auto const store = store_with_create(R"({"type":"m.room.create","content":{"creator":"@a:example.org"}})");

        WHEN("the stored version is resolved")
        {
            THEN("the room is version 1, which has no policy here")
            {
                REQUIRE(stored_room_version(store, "!r:example.org") == std::optional<std::string>{"1"});
                REQUIRE(stored_room_version_policy(store, "!r:example.org") == nullptr);
            }
        }
    }

    GIVEN("create events that declare nothing usable")
    {
        auto const non_string = store_with_create(R"({"type":"m.room.create","content":{"room_version":10}})");
        auto const no_content = store_with_create(R"({"type":"m.room.create"})");
        auto const unparseable = store_with_create("{not json");
        auto const unknown = store_with_create(R"({"type":"m.room.create","content":{"room_version":"99"}})");

        WHEN("the stored version is resolved")
        {
            THEN("none resolves to a supported version or a default")
            {
                for (auto const* store : {&non_string, &no_content, &unparseable, &unknown})
                {
                    REQUIRE(stored_room_version(*store, "!r:example.org").has_value());
                    REQUIRE(stored_room_version_policy(*store, "!r:example.org") == nullptr);
                }
                REQUIRE(stored_room_version(non_string, "!r:example.org") == std::optional<std::string>{""});
            }
        }
    }

    GIVEN("a store with no create event for the room")
    {
        auto const store = merovingian::database::PersistentStore{};

        WHEN("the stored version is resolved")
        {
            THEN("the version is unknown, and there is no policy")
            {
                REQUIRE_FALSE(stored_room_version(store, "!r:example.org").has_value());
                REQUIRE(stored_room_version_policy(store, "!r:example.org") == nullptr);
            }
        }
    }
}
