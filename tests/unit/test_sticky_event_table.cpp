// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The in-memory copy of `sticky_events` (migration 005, ADR-0854): what a row must be to be stored, that every reader
// takes the clock and never returns an expired row, the orderings (by room, by sender, by expiry) and that no reader
// scans the table, proved with `rows_examined`.
#include "merovingian/database/PersistentStickyEvent.hpp"
#include "merovingian/database/StickyEventTable.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <utility>
#include <vector>

namespace
{

namespace db = merovingian::database;
using db::PersistentStickyEvent;

constexpr auto room_a = "!a:example.org";
constexpr auto room_b = "!b:example.org";
constexpr auto alice = "@alice:example.org";
constexpr auto bob = "@bob:example.org";

[[nodiscard]] auto sticky(std::string event_id, std::int64_t expires_at_ms, std::string sender = alice,
                          std::string room = room_a) -> PersistentStickyEvent
{
    return {std::move(event_id), std::move(room), std::move(sender), 1, expires_at_ms};
}

[[nodiscard]] auto ids_of(std::vector<PersistentStickyEvent const*> const& rows) -> std::vector<std::string>
{
    auto ids = std::vector<std::string>{};
    for (auto const* found : rows)
    {
        ids.push_back(found->event_id);
    }
    return ids;
}

} // namespace

SCENARIO("A sticky event row is stored once and only within its caps", "[database][sticky-events]")
{
    GIVEN("an empty table")
    {
        auto table = db::StickyEventTable{};

        WHEN("a valid row is inserted twice")
        {
            auto const first = table.insert(sticky("$one", 5000));
            auto const second = table.insert(sticky("$one", 9000, bob, room_b));

            THEN("the second is refused and the first is unchanged")
            {
                REQUIRE(first);
                REQUIRE_FALSE(second);
                REQUIRE(table.size() == 1U);
                REQUIRE(table.find("$one", 1000)->sender == alice);
                REQUIRE(table.find("$one", 1000)->expires_at_ms == 5000);
                REQUIRE(table.unexpired_of_room(room_b, 1000).empty());
            }
        }

        WHEN("rows with an empty field, an over-long field, a NUL byte or a negative time are inserted")
        {
            auto const empty_id = table.insert(sticky("", 5000));
            auto const empty_sender = table.insert(sticky("$a", 5000, ""));
            auto const empty_room = table.insert(sticky("$b", 5000, alice, ""));
            auto const long_id = table.insert(sticky("$" + std::string(255U, 'x'), 5000));
            auto const nul_sender = table.insert(sticky("$c", 5000, std::string{"@a\0b:x", 6U}));
            auto const negative = table.insert(sticky("$d", -1));
            auto const at_cap = table.insert(sticky(std::string(255U, 'y'), 5000, std::string(255U, 'z'),
                                                    std::string(255U, 'r')));

            THEN("each is refused, and a row exactly at the cap is stored")
            {
                REQUIRE_FALSE(empty_id);
                REQUIRE_FALSE(empty_sender);
                REQUIRE_FALSE(empty_room);
                REQUIRE_FALSE(long_id);
                REQUIRE_FALSE(nul_sender);
                REQUIRE_FALSE(negative);
                REQUIRE(at_cap);
                REQUIRE(table.size() == 1U);
            }
        }
    }
}

SCENARIO("Every reader of the sticky event table ignores an expired row", "[database][sticky-events]")
{
    GIVEN("a table holding an expired row, a row expiring at the clock, and two live rows")
    {
        auto table = db::StickyEventTable{};
        REQUIRE(table.insert(sticky("$old", 500)));
        REQUIRE(table.insert(sticky("$edge", 1000)));
        REQUIRE(table.insert(sticky("$live-b", 3000)));
        REQUIRE(table.insert(sticky("$live-a", 2000)));

        WHEN("the readers ask at 1000")
        {
            THEN("a row whose expiry is at or before the clock is never returned, and the rest come in expiry order")
            {
                REQUIRE(table.find("$old", 1000) == nullptr);
                REQUIRE(table.find("$edge", 1000) == nullptr);
                REQUIRE(table.find("$live-a", 1000) != nullptr);
                REQUIRE(table.contains("$old"));
                REQUIRE(ids_of(table.unexpired_of_room(room_a, 1000)) ==
                        std::vector<std::string>{"$live-a", "$live-b"});
                REQUIRE(table.unexpired_count_of_sender(alice, 1000) == 2U);
                REQUIRE(ids_of(table.oldest_unexpired_of_sender(alice, 1000, 10U)) ==
                        std::vector<std::string>{"$live-a", "$live-b"});
                REQUIRE(ids_of(table.expired_at(1000, 10U)) == std::vector<std::string>{"$old", "$edge"});
            }
        }

        WHEN("the readers ask later, at 2500")
        {
            THEN("only the row expiring after that is returned")
            {
                REQUIRE(ids_of(table.unexpired_of_room(room_a, 2500)) == std::vector<std::string>{"$live-b"});
                REQUIRE(table.unexpired_count_of_sender(alice, 2500) == 1U);
                REQUIRE(table.find("$live-a", 2500) == nullptr);
            }
        }

        WHEN("the readers ask at the largest clock value")
        {
            THEN("nothing is unexpired and nothing is returned")
            {
                auto const largest = std::numeric_limits<std::int64_t>::max();
                REQUIRE(table.unexpired_of_room(room_a, largest).empty());
                REQUIRE(table.unexpired_count_of_sender(alice, largest) == 0U);
                REQUIRE(table.oldest_unexpired_of_sender(alice, largest, 5U).empty());
            }
        }
    }
}

SCENARIO("The sticky event table orders a sender's rows by expiry and then event ID", "[database][sticky-events]")
{
    GIVEN("a sender holding rows that expire together, one sooner and one later, and another sender's row")
    {
        auto table = db::StickyEventTable{};
        REQUIRE(table.insert(sticky("$c", 2000)));
        REQUIRE(table.insert(sticky("$a", 2000)));
        REQUIRE(table.insert(sticky("$b", 2000)));
        REQUIRE(table.insert(sticky("$late", 9000)));
        REQUIRE(table.insert(sticky("$soon", 1500)));
        REQUIRE(table.insert(sticky("$bob", 100'000, bob)));

        WHEN("the oldest two and then all of them are asked for")
        {
            auto const two = table.oldest_unexpired_of_sender(alice, 1000, 2U);
            auto const all = table.oldest_unexpired_of_sender(alice, 1000, 100U);

            THEN("the order is expiry, ties by event ID, and the other sender is not mixed in")
            {
                REQUIRE(ids_of(two) == std::vector<std::string>{"$soon", "$a"});
                REQUIRE(ids_of(all) == std::vector<std::string>{"$soon", "$a", "$b", "$c", "$late"});
                REQUIRE(table.unexpired_count_of_sender(alice, 1000) == 5U);
                REQUIRE(table.unexpired_count_of_sender(bob, 1000) == 1U);
                REQUIRE(table.unexpired_count_of_sender("@nobody:example.org", 1000) == 0U);
            }
        }
    }
}

SCENARIO("A sticky event table reader looks only at the rows it returns", "[database][sticky-events]")
{
    GIVEN("a table of 3000 rows over 300 rooms and 100 senders, and a sender with 10 expired and 5 live rows")
    {
        auto table = db::StickyEventTable{};
        for (auto index = 0; index < 3000; ++index)
        {
            REQUIRE(table.insert(sticky("$bulk-" + std::to_string(index), 10'000 + index,
                                        "@u" + std::to_string(index % 100) + ":example.org",
                                        "!r" + std::to_string(index % 300) + ":example.org")));
        }
        for (auto index = 0; index < 10; ++index)
        {
            REQUIRE(table.insert(sticky("$gone-" + std::to_string(index), 100 + index, "@mixed:example.org",
                                        "!mixed:example.org")));
        }
        for (auto index = 0; index < 5; ++index)
        {
            REQUIRE(table.insert(sticky("$live-" + std::to_string(index), 50'000 + index, "@mixed:example.org",
                                        "!mixed:example.org")));
        }

        WHEN("each reader runs once")
        {
            auto const before_find = table.rows_examined();
            auto const* found = table.find("$bulk-1234", 1000);
            auto const find_cost = table.rows_examined() - before_find;

            auto const before_room = table.rows_examined();
            auto const room_rows = table.unexpired_of_room("!mixed:example.org", 1000);
            auto const room_cost = table.rows_examined() - before_room;

            auto const before_oldest = table.rows_examined();
            auto const oldest = table.oldest_unexpired_of_sender("@mixed:example.org", 1000, 1U);
            auto const oldest_cost = table.rows_examined() - before_oldest;

            auto const before_count = table.rows_examined();
            auto const count = table.unexpired_count_of_sender("@u7:example.org", 1000);
            auto const count_cost = table.rows_examined() - before_count;

            auto const before_expired = table.rows_examined();
            auto const expired = table.expired_at(1000, 4U);
            auto const expired_cost = table.rows_examined() - before_expired;

            THEN("the cost is the rows returned, not the size of the table")
            {
                REQUIRE(found != nullptr);
                REQUIRE(find_cost == 1U);
                REQUIRE(room_rows.size() == 5U);
                REQUIRE(room_cost == 5U);
                REQUIRE(oldest.size() == 1U);
                REQUIRE(oldest[0]->event_id == "$live-0");
                REQUIRE(oldest_cost == 1U);
                REQUIRE(count == 30U);
                REQUIRE(count_cost == 0U);
                REQUIRE(expired.size() == 4U);
                REQUIRE(expired_cost == 4U);
            }
        }

        WHEN("a sender's count is read while that sender holds expired rows")
        {
            auto const before = table.rows_examined();
            auto const count = table.unexpired_count_of_sender("@mixed:example.org", 1000);
            auto const cost = table.rows_examined() - before;

            THEN("only the expired rows at the front were walked")
            {
                REQUIRE(count == 5U);
                REQUIRE(cost == 10U);
            }
        }
    }
}

SCENARIO("Erasing sticky event rows keeps every index in step", "[database][sticky-events]")
{
    GIVEN("rows of two senders in two rooms")
    {
        auto table = db::StickyEventTable{};
        REQUIRE(table.insert(sticky("$a1", 2000, alice, room_a)));
        REQUIRE(table.insert(sticky("$a2", 3000, alice, room_b)));
        REQUIRE(table.insert(sticky("$b1", 4000, bob, room_a)));
        REQUIRE(table.insert(sticky("$b2", 100, bob, room_b)));

        WHEN("one row is erased")
        {
            auto const erased = table.erase("$a1");
            auto const again = table.erase("$a1");

            THEN("it leaves every index and a second erase finds nothing")
            {
                REQUIRE(erased);
                REQUIRE_FALSE(again);
                REQUIRE(table.size() == 3U);
                REQUIRE(ids_of(table.unexpired_of_room(room_a, 1000)) == std::vector<std::string>{"$b1"});
                REQUIRE(table.unexpired_count_of_sender(alice, 1000) == 1U);
                REQUIRE(ids_of(table.expired_at(1000, 10U)) == std::vector<std::string>{"$b2"});
            }
        }

        WHEN("a sender's rows are erased")
        {
            auto const removed = table.erase_sender(bob);

            THEN("both go, from every index, and the other sender is untouched")
            {
                REQUIRE(removed == 2U);
                REQUIRE(table.size() == 2U);
                REQUIRE_FALSE(table.contains("$b1"));
                REQUIRE_FALSE(table.contains("$b2"));
                REQUIRE(table.expired_at(1000, 10U).empty());
                REQUIRE(table.unexpired_count_of_sender(bob, 1000) == 0U);
                REQUIRE(table.unexpired_count_of_sender(alice, 1000) == 2U);
                REQUIRE(table.erase_sender(bob) == 0U);
            }
        }

        WHEN("the expired rows are erased at 3000")
        {
            auto const removed = table.erase_expired(3000);

            THEN("every row expiring at or before 3000 goes")
            {
                REQUIRE(removed == 3U);
                REQUIRE(table.size() == 1U);
                REQUIRE(table.contains("$b1"));
                REQUIRE_FALSE(table.contains("$a2"));
                REQUIRE_FALSE(table.contains("$a1"));
                REQUIRE_FALSE(table.contains("$b2"));
            }
        }

        WHEN("the table is copied and then cleared")
        {
            auto copy = table;
            table.clear();

            THEN("the copy answers from its own indexes and the original is empty")
            {
                REQUIRE(table.size() == 0U);
                REQUIRE(table.unexpired_of_room(room_a, 0).empty());
                REQUIRE(copy.size() == 4U);
                REQUIRE(ids_of(copy.unexpired_of_room(room_a, 0)) == std::vector<std::string>{"$a1", "$b1"});
                REQUIRE(copy.insert(sticky("$a1", 1)) == false);
            }
        }
    }
}
