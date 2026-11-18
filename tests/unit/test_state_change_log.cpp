// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The state change log (ADR-0827): what `/sync`'s `state_after` reads to tell a client exactly what changed between two
// positions. A change is filed above every position already served, a position before the log started or past what it
// still holds is not covered, and both bounds hold.

#include "merovingian/database/StateChangeLog.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

namespace
{

namespace db = merovingian::database;

constexpr auto room_id = std::string_view{"!room:example.org"};
constexpr auto other_room_id = std::string_view{"!other:example.org"};

// The event IDs of the changes `log` holds for `room` above `position`, in its order.
[[nodiscard]] auto event_ids_after(db::StateChangeLog const& log, std::string_view room, std::uint64_t position)
    -> std::vector<std::string>
{
    auto ids = std::vector<std::string>{};
    for (auto const* change : log.changes_after(room, position))
    {
        ids.push_back(change->event_id);
    }
    return ids;
}

// The position `log` filed the one change of `room` above `position` at.
[[nodiscard]] auto only_position_after(db::StateChangeLog const& log, std::string_view room, std::uint64_t position)
    -> std::uint64_t
{
    auto const changes = log.changes_after(room, position);
    REQUIRE(changes.size() == 1U);
    return changes.front()->position;
}

} // namespace

SCENARIO("The state change log records nothing until it starts", "[database][state-change-log]")
{
    GIVEN("a log that has not been started, as in the federation worker")
    {
        auto log = db::StateChangeLog{};

        WHEN("a change is recorded")
        {
            log.record(room_id, "m.room.topic", "", "$a", "$b", 5U);

            THEN("nothing is held and no position is covered")
            {
                REQUIRE_FALSE(log.active());
                REQUIRE(log.size() == 0U);
                REQUIRE_FALSE(log.covers(room_id, 5U));
                REQUIRE_FALSE(log.has_change_after(room_id, 0U));
            }
        }
    }
}

SCENARIO("A started log covers positions from its floor and files changes above it", "[database][state-change-log]")
{
    GIVEN("a log started at position 10")
    {
        auto log = db::StateChangeLog{};
        log.start(10U);

        THEN("a position at or below the floor is not covered and one above it is")
        {
            REQUIRE(log.active());
            REQUIRE_FALSE(log.covers(room_id, 9U));
            REQUIRE_FALSE(log.covers(room_id, 10U));
            REQUIRE(log.covers(room_id, 11U));
        }

        WHEN("a change caused by an event ordered at or below the floor is recorded")
        {
            log.record(room_id, "m.room.topic", "", "$a", "$b", 3U);

            THEN("it is filed above the floor, so the state at the floor is unchanged")
            {
                REQUIRE(only_position_after(log, room_id, 10U) == 11U);
                REQUIRE(log.has_change_after(room_id, 10U));
                REQUIRE_FALSE(log.has_change_after(room_id, 11U));
            }
        }

        WHEN("a change caused by an event ordered above the floor is recorded")
        {
            log.record(room_id, "m.room.topic", "", "$a", "$b", 25U);

            THEN("it is filed at that event's ordering")
            {
                REQUIRE(only_position_after(log, room_id, 10U) == 25U);
            }
        }

        WHEN("a change caused by no event is recorded")
        {
            log.record(room_id, "m.room.topic", "", "$a", "$b", 0U);

            THEN("it is filed just above the floor")
            {
                REQUIRE(only_position_after(log, room_id, 10U) == 11U);
            }
        }

        WHEN("a write that leaves the value unchanged is recorded")
        {
            log.record(room_id, "m.room.topic", "", "$a", "$a", 20U);

            THEN("nothing is held")
            {
                REQUIRE(log.size() == 0U);
            }
        }
    }
}

SCENARIO("A change is never filed at or below a position a sync has answered at", "[database][state-change-log]")
{
    GIVEN("a log started at 10 that has answered a sync at 40")
    {
        auto log = db::StateChangeLog{};
        log.start(10U);
        log.note_served(40U);

        WHEN("an event ordered at 30, a backfilled one, changes the state")
        {
            log.record(room_id, "m.room.topic", "", "$a", "$b", 30U);

            THEN("the change is filed at 41, so the state the client was told at 40 still holds at 40")
            {
                REQUIRE(only_position_after(log, room_id, 10U) == 41U);
                REQUIRE(event_ids_after(log, room_id, 40U) == std::vector<std::string>{"$b"});
            }
        }

        WHEN("a sync at a lower position is noted afterwards")
        {
            log.note_served(20U);
            log.record(room_id, "m.room.topic", "", "$a", "$b", 0U);

            THEN("the highest position served still holds")
            {
                REQUIRE(only_position_after(log, room_id, 10U) == 41U);
            }
        }

        WHEN("the last representable position has been served")
        {
            log.note_served(std::numeric_limits<std::uint64_t>::max());
            log.record(room_id, "m.room.topic", "", "$a", "$b", 0U);

            THEN("the change is filed there, without wrapping, and changes_after the maximum is empty")
            {
                REQUIRE(only_position_after(log, room_id, 10U) == std::numeric_limits<std::uint64_t>::max());
                REQUIRE(log.changes_after(room_id, std::numeric_limits<std::uint64_t>::max()).empty());
            }
        }
    }
}

SCENARIO("Changes come back by position and, at one position, in the order they were made",
         "[database][state-change-log]")
{
    GIVEN("a started log with changes in two rooms")
    {
        auto log = db::StateChangeLog{};
        log.start(0U);
        log.record(room_id, "m.room.topic", "", "$a", "$c", 20U);
        log.record(room_id, "m.room.topic", "", "", "$a", 10U);
        log.record(other_room_id, "m.room.topic", "", "", "$other", 15U);
        log.record(room_id, "m.room.name", "", "", "$n1", 20U);
        log.record(room_id, "m.room.name", "", "$n1", "$n2", 20U);

        WHEN("the room's changes above 0 are read")
        {
            auto const before = log.rows_examined().value();
            auto const ids = event_ids_after(log, room_id, 0U);

            THEN("they are ordered by position, then by the order recorded, and only that room's")
            {
                REQUIRE(ids == std::vector<std::string>{"$a", "$c", "$n1", "$n2"});
                REQUIRE(log.rows_examined().value() - before == 4U);
            }
        }

        WHEN("the room's changes above 10 are read")
        {
            auto const before = log.rows_examined().value();
            auto const ids = event_ids_after(log, room_id, 10U);

            THEN("only the changes above 10 are examined")
            {
                REQUIRE(ids == std::vector<std::string>{"$c", "$n1", "$n2"});
                REQUIRE(log.rows_examined().value() - before == 3U);
            }
        }

        WHEN("a room with no changes is read")
        {
            THEN("nothing is returned and the room is covered")
            {
                REQUIRE(log.changes_after("!quiet:example.org", 0U).empty());
                REQUIRE(log.covers("!quiet:example.org", 1U));
            }
        }
    }
}

SCENARIO("Dropping a room's oldest change raises its horizon", "[database][state-change-log]")
{
    GIVEN("a started log holding as many changes of one room as it allows")
    {
        auto log = db::StateChangeLog{};
        log.start(0U);
        for (auto index = std::size_t{0U}; index < db::StateChangeLog::max_changes_per_room; ++index)
        {
            log.record(room_id, "org.example.key", std::to_string(index), "", "$e" + std::to_string(index),
                       100U + index);
        }
        REQUIRE(log.size() == db::StateChangeLog::max_changes_per_room);
        REQUIRE(log.covers(room_id, 1U));

        WHEN("one more change is recorded")
        {
            log.record(room_id, "org.example.key", "late", "", "$late", 5000U);

            THEN("the oldest is dropped and positions at or below it are no longer covered")
            {
                REQUIRE(log.size() == db::StateChangeLog::max_changes_per_room);
                REQUIRE_FALSE(log.covers(room_id, 1U));
                REQUIRE_FALSE(log.covers(room_id, 99U));
                REQUIRE(log.covers(room_id, 100U));
                REQUIRE(log.covers(other_room_id, 1U));
            }
        }
    }
}

SCENARIO("The log holds at most max_changes changes in all", "[database][state-change-log]")
{
    GIVEN("a started log filled with one change in each of max_changes rooms")
    {
        auto log = db::StateChangeLog{};
        log.start(0U);
        for (auto index = std::size_t{0U}; index < db::StateChangeLog::max_changes; ++index)
        {
            log.record("!r" + std::to_string(index) + ":example.org", "m.room.topic", "", "", "$t", 1U + index);
        }
        REQUIRE(log.size() == db::StateChangeLog::max_changes);

        WHEN("one more change is recorded in another room")
        {
            log.record(room_id, "m.room.topic", "", "", "$t", 1000000U);

            THEN("the oldest change of all is dropped and its room is no longer covered below it")
            {
                REQUIRE(log.size() == db::StateChangeLog::max_changes);
                REQUIRE_FALSE(log.covers("!r0:example.org", 0U));
                REQUIRE(log.covers("!r0:example.org", 1U));
                REQUIRE(log.covers("!r1:example.org", 1U));
                REQUIRE(log.covers(room_id, 1U));
            }
        }
    }
}

SCENARIO("Starting the log again forgets what it held", "[database][state-change-log]")
{
    GIVEN("a log holding a change")
    {
        auto log = db::StateChangeLog{};
        log.start(0U);
        log.record(room_id, "m.room.topic", "", "", "$t", 5U);

        WHEN("it is started again at 50")
        {
            log.start(50U);

            THEN("nothing is held and only positions above 50 are covered")
            {
                REQUIRE(log.size() == 0U);
                REQUIRE_FALSE(log.covers(room_id, 50U));
                REQUIRE(log.covers(room_id, 51U));
            }
        }
    }
}
