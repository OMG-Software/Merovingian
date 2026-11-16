// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/database/PersistentEvent.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/sync/RoomReadAccess.hpp"
#include "merovingian/sync/RoomReadKind.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <utility>

namespace
{

using merovingian::database::PersistentEvent;
using merovingian::database::PersistentStore;
using merovingian::sync::RoomReadAccess;
using merovingian::sync::RoomReadKind;

constexpr auto room = "!room:example.org";

[[nodiscard]] auto make_event(std::string event_id, std::uint64_t stream_ordering, std::string status = "accepted")
    -> PersistentEvent
{
    auto event = PersistentEvent{std::move(event_id),
                                 room,
                                 "@alice:example.org",
                                 R"({"type":"m.room.message","content":{"body":"hello"}})",
                                 stream_ordering,
                                 stream_ordering,
                                 {},
                                 {},
                                 {}};
    event.status = std::move(status);
    return event;
}

[[nodiscard]] auto current_access() -> RoomReadAccess
{
    return RoomReadAccess{RoomReadKind::current, {}, 0U};
}

} // namespace

SCENARIO("The state anchor of a room is found without visiting the rows above the position", "[sync][state-anchor]")
{
    GIVEN("a room with an old event and thousands of newer ones")
    {
        auto store = PersistentStore{};
        REQUIRE(store.events.insert(make_event("$old", 5U)));
        for (auto ordering = std::uint64_t{100U}; ordering < 3100U; ++ordering)
        {
            REQUIRE(store.events.insert(make_event("$new" + std::to_string(ordering), ordering)));
        }

        WHEN("the anchor at a position below all the newer events is read")
        {
            auto const before = store.state_anchor_rows_examined.value();
            auto const* const anchor = merovingian::sync::state_anchor_event(store, room, current_access(), 50U);
            auto const examined = store.state_anchor_rows_examined.value() - before;

            THEN("it is the old event, found by examining one row, not the 3000 above the position")
            {
                REQUIRE(anchor != nullptr);
                REQUIRE(anchor->event_id == "$old");
                REQUIRE(examined == 1U);
            }
        }

        WHEN("the anchor is read with no position")
        {
            auto const* const anchor =
                merovingian::sync::state_anchor_event(store, room, current_access(), std::nullopt);

            THEN("it is the newest event")
            {
                REQUIRE(anchor != nullptr);
                REQUIRE(anchor->event_id == "$new3099");
            }
        }
    }

    GIVEN("rows sharing the newest ordering at the position, the newest added row being withheld")
    {
        auto store = PersistentStore{};
        REQUIRE(store.events.insert(make_event("$first", 20U)));
        REQUIRE(store.events.insert(make_event("$second", 20U)));
        REQUIRE(store.events.insert(make_event("$withheld", 20U, "rejected")));
        REQUIRE(store.events.insert(make_event("$above", 30U)));

        WHEN("the anchor at 25 is read")
        {
            auto const* const anchor = merovingian::sync::state_anchor_event(store, room, current_access(), 25U);

            THEN("the row added first among the accepted rows of that ordering wins")
            {
                REQUIRE(anchor != nullptr);
                REQUIRE(anchor->event_id == "$first");
            }
        }
    }

    GIVEN("a withheld event at the position and an accepted one below it")
    {
        auto store = PersistentStore{};
        REQUIRE(store.events.insert(make_event("$below", 10U)));
        REQUIRE(store.events.insert(make_event("$soft", 20U, "soft_failed")));

        WHEN("the anchor at 20 is read")
        {
            auto const* const anchor = merovingian::sync::state_anchor_event(store, room, current_access(), 20U);

            THEN("the withheld row is stepped over")
            {
                REQUIRE(anchor != nullptr);
                REQUIRE(anchor->event_id == "$below");
            }
        }
    }

    GIVEN("a room whose events all lie above the position")
    {
        auto store = PersistentStore{};
        REQUIRE(store.events.insert(make_event("$a", 10U)));

        WHEN("the anchor at 5 is read")
        {
            auto const* const anchor = merovingian::sync::state_anchor_event(store, room, current_access(), 5U);

            THEN("there is no anchor")
            {
                REQUIRE(anchor == nullptr);
            }
        }
    }
}
