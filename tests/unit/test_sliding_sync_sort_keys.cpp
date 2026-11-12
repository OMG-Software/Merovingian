// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
// Security audit run 3, finding C07 follow-up: the `by_recency` (with bump_event_types) and `by_name` sort keys are
// read per room through the room indexes, so their cost does not grow with other rooms' events and state (ADR-0666).
//
// Spec: MSC4186 list `sort`: by_recency ("the most recent event in the room, optionally counting only
// `bump_event_types`") and by_name.

#include "merovingian/database/PersistentEvent.hpp"
#include "merovingian/database/PersistentStateEvent.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/sync/SlidingSyncRequestLookups.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

namespace
{

namespace db = merovingian::database;
namespace sync = merovingian::sync;

constexpr auto alice = "@alice:example.org";
constexpr auto mine = "!mine:example.org";

auto add_event(db::PersistentStore& store, std::string const& room_id, std::string const& type, std::uint64_t ordering,
               std::string const& content = "{}") -> std::string
{
    auto event = db::PersistentEvent{};
    event.event_id = "$e" + std::to_string(ordering) + room_id;
    event.room_id = room_id;
    event.sender_user_id = "@bob:example.org";
    event.json = R"({"type":")" + type + R"(","content":)" + content + "}";
    event.stream_ordering = ordering;
    auto const id = event.event_id;
    store.events.push_back(std::move(event));
    return id;
}

// `unrelated` other rooms, each with `events_each` events and a name.
auto add_unrelated_rooms(db::PersistentStore& store, std::size_t unrelated, std::size_t events_each) -> void
{
    auto ordering = std::uint64_t{100'000U};
    for (auto number = std::size_t{0U}; number < unrelated; ++number)
    {
        auto const room = "!other" + std::to_string(number) + ":example.org";
        for (auto index = std::size_t{0U}; index < events_each; ++index)
        {
            std::ignore = add_event(store, room, "m.room.message", ++ordering);
        }
        auto const name_id = add_event(store, room, "m.room.name", ++ordering, R"({"name":"other"})");
        store.state.push_back(db::PersistentStateEvent{room, "m.room.name", "", name_id});
    }
}

// The room `mine`: a name, then messages 1..5 and a reaction at 6 (newest).
auto add_my_room(db::PersistentStore& store) -> void
{
    auto const name_id = add_event(store, mine, "m.room.name", 1U, R"({"name":"Alpha"})");
    store.state.push_back(db::PersistentStateEvent{mine, "m.room.name", "", name_id});
    for (auto ordering = std::uint64_t{2U}; ordering <= 5U; ++ordering)
    {
        std::ignore = add_event(store, mine, "m.room.message", ordering);
    }
    std::ignore = add_event(store, mine, "m.reaction", 6U);
}

[[nodiscard]] auto finish(db::PersistentStore store) -> db::PersistentStore
{
    db::rebuild_state_index(store);
    return store;
}

} // namespace

SCENARIO("The recency and name sort keys read the room's own rows", "[sync][sliding-sync][c07][unit]")
{
    GIVEN("one room with a name, four messages and a reaction")
    {
        auto store = db::PersistentStore{};
        add_my_room(store);
        auto const held = finish(std::move(store));
        auto lookups = sync::SlidingSyncRequestLookups{held, alice};

        WHEN("the keys are asked for")
        {
            THEN("recency is the newest event, or the newest of the bump types, and the name is the room's")
            {
                REQUIRE(lookups.recency(mine, {}) == 6U);
                REQUIRE(lookups.recency(mine, {"m.room.message"}) == 5U);
                REQUIRE(lookups.recency(mine, {"m.reaction", "m.room.message"}) == 6U);
                REQUIRE(lookups.recency(mine, {"m.room.topic"}) == 0U);
                REQUIRE(lookups.room_name(mine) == "Alpha");
                REQUIRE(lookups.room_name("!unknown:example.org").empty());
            }
        }
    }
}

SCENARIO("The recency and name sort keys cost the room, not the other rooms' events and state",
         "[sync][sliding-sync][c07][unit]")
{
    GIVEN("the same room beside no other room and beside 40 rooms of 100 events each")
    {
        auto alone = db::PersistentStore{};
        add_my_room(alone);
        auto const alone_store = finish(std::move(alone));
        auto crowded = db::PersistentStore{};
        add_unrelated_rooms(crowded, 40U, 100U);
        add_my_room(crowded);
        auto const crowded_store = finish(std::move(crowded));
        auto alone_lookups = sync::SlidingSyncRequestLookups{alone_store, alice};
        auto crowded_lookups = sync::SlidingSyncRequestLookups{crowded_store, alice};

        WHEN("both stores answer the three keys for the room")
        {
            auto const bumped_alone = alone_lookups.recency(mine, {"m.room.message"});
            auto const bumped_crowded = crowded_lookups.recency(mine, {"m.room.message"});
            std::ignore = alone_lookups.room_name(mine);
            std::ignore = crowded_lookups.room_name(mine);

            THEN("the answers are equal and the rows visited are the room's own, the same in both")
            {
                REQUIRE(bumped_alone == 5U);
                REQUIRE(bumped_crowded == 5U);
                REQUIRE(alone_lookups.recency_rows_visited() == 2U);
                REQUIRE(crowded_lookups.recency_rows_visited() == alone_lookups.recency_rows_visited());
            }
        }
    }
}

SCENARIO("A room whose bump types are not found within the budget falls back to its newest event",
         "[sync][sliding-sync][c07][unit]")
{
    GIVEN("a room of 1,500 messages")
    {
        auto store = db::PersistentStore{};
        for (auto ordering = std::uint64_t{1U}; ordering <= 1'500U; ++ordering)
        {
            std::ignore = add_event(store, mine, "m.room.message", ordering);
        }
        auto const held = finish(std::move(store));

        WHEN("a type that no event has is asked for")
        {
            auto lookups = sync::SlidingSyncRequestLookups{held, alice};
            auto const key = lookups.recency(mine, {"m.reaction"});

            THEN("1,000 rows were read and the newest event's ordering stands in")
            {
                REQUIRE(lookups.recency_rows_visited() == sync::max_recency_rows_examined);
                REQUIRE(key == 1'500U);
            }
        }
        WHEN("the bump type is the 1,000th row from the newest and then the 1,001st")
        {
            auto at_budget = db::PersistentStore{};
            auto beyond_budget = db::PersistentStore{};
            for (auto ordering = std::uint64_t{1U}; ordering <= 1'500U; ++ordering)
            {
                auto const type_at_budget = ordering == 501U ? "m.reaction" : "m.room.message";
                auto const type_beyond = ordering == 500U ? "m.reaction" : "m.room.message";
                std::ignore = add_event(at_budget, mine, type_at_budget, ordering);
                std::ignore = add_event(beyond_budget, mine, type_beyond, ordering);
            }
            auto const at_store = finish(std::move(at_budget));
            auto const beyond_store = finish(std::move(beyond_budget));
            auto at_lookups = sync::SlidingSyncRequestLookups{at_store, alice};
            auto beyond_lookups = sync::SlidingSyncRequestLookups{beyond_store, alice};

            THEN("the first is found and the second falls back to the newest")
            {
                REQUIRE(at_lookups.recency(mine, {"m.reaction"}) == 501U);
                REQUIRE(beyond_lookups.recency(mine, {"m.reaction"}) == 1'500U);
            }
        }
    }
}
