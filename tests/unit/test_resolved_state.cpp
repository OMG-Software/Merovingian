// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// A room's resolved state as of a sync position, rebuilt from its current state and the state change log (ADR-0827):
// the state a `state_after` client is told, and the exact delta between two such positions, whatever made the state
// change and in whatever order.

#include "merovingian/database/PersistentEvent.hpp"
#include "merovingian/database/PersistentStateEvent.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/sync/ResolvedState.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace
{

namespace db = merovingian::database;
namespace sync = merovingian::sync;

constexpr auto room_id = std::string_view{"!room:example.org"};

// Stores a state event of `type` and `state_key` at `ordering`, so that store_state accepts a row naming it.
auto store_state_event(db::PersistentStore& store, std::string_view type, std::string_view state_key,
                       std::string const& event_id, std::uint64_t ordering) -> void
{
    auto event = db::PersistentEvent{};
    event.event_id = event_id;
    event.room_id = std::string{room_id};
    event.sender_user_id = "@alice:example.org";
    event.depth = ordering;
    event.stream_ordering = ordering;
    event.json = std::string{R"({"type":")"} + std::string{type} + R"(","state_key":")" + std::string{state_key} +
                 R"(","room_id":")" + std::string{room_id} + R"(","sender":"@alice:example.org","content":{}})";
    REQUIRE(db::store_event(store, std::move(event)));
}

// Makes `event_id` the room's current value of (`type`, `state_key`), as made by the event at `causing`.
auto set_current(db::PersistentStore& store, std::string_view type, std::string_view state_key,
                 std::string const& event_id, std::uint64_t causing) -> void
{
    REQUIRE(
        db::store_state(store, {std::string{room_id}, std::string{type}, std::string{state_key}, event_id}, causing));
}

[[nodiscard]] auto sorted(std::vector<std::string> ids) -> std::vector<std::string>
{
    std::ranges::sort(ids);
    return ids;
}

} // namespace

SCENARIO("Nothing is rebuilt while the state change log is inactive", "[sync][state-change-log]")
{
    GIVEN("a store whose log was never started, as in the federation worker")
    {
        auto store = db::PersistentStore{};
        store_state_event(store, "m.room.topic", "", "$a", 1U);
        set_current(store, "m.room.topic", "", "$a", 1U);

        THEN("no position is covered")
        {
            REQUIRE_FALSE(sync::resolved_state_at(store, room_id, 5U).has_value());
            REQUIRE_FALSE(sync::resolved_state_changes(store, room_id, 5U, 6U).has_value());
            REQUIRE_FALSE(sync::resolved_state_event_at(store, room_id, "m.room.topic", "", 5U).has_value());
            REQUIRE(store.state_change_log.size() == 0U);
        }
    }
}

SCENARIO("A key resolution moves back after a sync is sent to the client that was told the other value",
         "[sync][state-change-log]")
{
    GIVEN("a room whose topic is A when a sync answers at 20")
    {
        auto store = db::PersistentStore{};
        store_state_event(store, "m.room.topic", "", "$a", 5U);
        store_state_event(store, "m.room.topic", "", "$b", 6U);
        set_current(store, "m.room.topic", "", "$a", 5U);
        store.state_change_log.start(10U);
        store.state_change_log.note_served(20U);

        WHEN("resolution moves the topic to B, a sync answers at 30, and resolution moves it back to A")
        {
            set_current(store, "m.room.topic", "", "$b", 0U);
            store.state_change_log.note_served(30U);
            set_current(store, "m.room.topic", "", "$a", 0U);

            THEN("each sync's state is the value it was told, and each delta is exact")
            {
                REQUIRE(sync::resolved_state_at(store, room_id, 20U) == std::vector<std::string>{"$a"});
                REQUIRE(sync::resolved_state_at(store, room_id, 30U) == std::vector<std::string>{"$b"});
                REQUIRE(sync::resolved_state_at(store, room_id, 31U) == std::vector<std::string>{"$a"});
                REQUIRE(sync::resolved_state_changes(store, room_id, 20U, 30U) == std::vector<std::string>{"$b"});
                REQUIRE(sync::resolved_state_changes(store, room_id, 30U, 31U) == std::vector<std::string>{"$a"});
            }

            THEN("a client that slept through both is sent nothing: it already has A")
            {
                REQUIRE(sync::resolved_state_changes(store, room_id, 20U, 31U) == std::vector<std::string>{});
            }

            THEN("the topic as of each position is looked up by key")
            {
                REQUIRE(sync::resolved_state_event_at(store, room_id, "m.room.topic", "", 30U) == "$b");
                REQUIRE(sync::resolved_state_event_at(store, room_id, "m.room.topic", "", 31U) == "$a");
                REQUIRE(sync::resolved_state_event_at(store, room_id, "m.room.name", "", 31U) == "");
            }
        }
    }
}

SCENARIO("A change caused by an event ordered at or below a served position is seen after it",
         "[sync][state-change-log]")
{
    GIVEN("a room whose topic is A when a sync answers at 30")
    {
        auto store = db::PersistentStore{};
        store_state_event(store, "m.room.topic", "", "$a", 5U);
        store_state_event(store, "m.room.topic", "", "$backfilled", 25U);
        set_current(store, "m.room.topic", "", "$a", 5U);
        store.state_change_log.start(10U);
        store.state_change_log.note_served(30U);

        WHEN("a backfilled event at 25 becomes the topic")
        {
            set_current(store, "m.room.topic", "", "$backfilled", 25U);

            THEN("the state as of 30 still says A, and the next delta carries the change")
            {
                REQUIRE(sync::resolved_state_at(store, room_id, 30U) == std::vector<std::string>{"$a"});
                REQUIRE(sync::resolved_state_changes(store, room_id, 30U, 31U) ==
                        std::vector<std::string>{"$backfilled"});
                REQUIRE(store.state_change_log.has_change_after(room_id, 30U));
            }
        }
    }
}

SCENARIO("A key removed from the current state is put back as of an earlier position", "[sync][state-change-log]")
{
    GIVEN("a room with a topic and a name when a sync answers at 20")
    {
        auto store = db::PersistentStore{};
        store_state_event(store, "m.room.topic", "", "$topic", 5U);
        store_state_event(store, "m.room.name", "", "$name", 6U);
        set_current(store, "m.room.topic", "", "$topic", 5U);
        set_current(store, "m.room.name", "", "$name", 6U);
        store.state_change_log.start(10U);
        store.state_change_log.note_served(20U);

        WHEN("resolution drops the name")
        {
            REQUIRE(db::remove_current_state_rows(store, room_id,
                                                  {
                                                      {"m.room.name", ""}
            },
                                                  {}, 0U));

            THEN("the state as of 20 still holds the name, and the delta sends nothing it cannot express")
            {
                REQUIRE(sorted(*sync::resolved_state_at(store, room_id, 20U)) ==
                        std::vector<std::string>{"$name", "$topic"});
                REQUIRE(sync::resolved_state_at(store, room_id, 21U) == std::vector<std::string>{"$topic"});
                REQUIRE(sync::resolved_state_changes(store, room_id, 20U, 21U) == std::vector<std::string>{});
            }
        }
    }
}

SCENARIO("A position the log does not cover is not rebuilt", "[sync][state-change-log]")
{
    GIVEN("a store whose log started at 10")
    {
        auto store = db::PersistentStore{};
        store_state_event(store, "m.room.topic", "", "$a", 5U);
        set_current(store, "m.room.topic", "", "$a", 5U);
        store.state_change_log.start(10U);

        THEN("a since at or below the start, which an earlier process answered, gives no delta")
        {
            REQUIRE_FALSE(sync::resolved_state_changes(store, room_id, 10U, 12U).has_value());
            REQUIRE_FALSE(sync::resolved_state_at(store, room_id, 10U).has_value());
            REQUIRE(sync::resolved_state_at(store, room_id, 11U) == std::vector<std::string>{"$a"});
        }
    }
}

SCENARIO("A delta over a window with no state change reads none of the room's state", "[sync][state-change-log]")
{
    GIVEN("a room with many state rows, synced at 20")
    {
        auto store = db::PersistentStore{};
        for (auto index = 0U; index < 50U; ++index)
        {
            auto const event_id = "$k" + std::to_string(index);
            store_state_event(store, "org.example.key", std::to_string(index), event_id, 1U + index);
            set_current(store, "org.example.key", std::to_string(index), event_id, 1U + index);
        }
        store.state_change_log.start(10U);
        store.state_change_log.note_served(20U);

        WHEN("the delta from 20 to 40 is taken")
        {
            auto const rows_before = store.state_rows_examined.value();
            auto const log_before = store.state_change_log.rows_examined().value();
            auto const changes = sync::resolved_state_changes(store, room_id, 20U, 40U);

            THEN("it is empty and reads no state row and no change")
            {
                REQUIRE(changes == std::vector<std::string>{});
                REQUIRE(store.state_rows_examined.value() == rows_before);
                REQUIRE(store.state_change_log.rows_examined().value() == log_before);
            }
        }

        WHEN("one key changes and the delta is taken")
        {
            store_state_event(store, "org.example.key", "7", "$k7b", 60U);
            set_current(store, "org.example.key", "7", "$k7b", 60U);
            auto const rows_before = store.state_rows_examined.value();
            auto const changes = sync::resolved_state_changes(store, room_id, 20U, 60U);

            THEN("it names that key and reads one state row")
            {
                REQUIRE(changes == std::vector<std::string>{"$k7b"});
                REQUIRE(store.state_rows_examined.value() - rows_before <= 1U);
            }
        }
    }
}
