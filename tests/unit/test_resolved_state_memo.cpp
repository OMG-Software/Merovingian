// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// ResolvedStateMemo: exact keys and a bounded size (ADR-0600).

#include "merovingian/database/PersistentStateGroupStateEntry.hpp"
#include "merovingian/database/ResolvedStateMemo.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <string>
#include <vector>

namespace
{

using merovingian::database::PersistentStateGroupStateEntry;
using merovingian::database::ResolvedStateMemo;

auto const key = std::vector<std::string>{"sg:a", "sg:b"};

[[nodiscard]] auto entries_of(std::size_t count) -> ResolvedStateMemo::Entries
{
    auto entries = ResolvedStateMemo::Entries{};
    for (std::size_t index = 0U; index < count; ++index)
    {
        entries.push_back(PersistentStateGroupStateEntry{{}, "m.room.topic", std::to_string(index), "$e"});
    }
    return entries;
}

[[nodiscard]] auto room_name(std::size_t index) -> std::string
{
    return "!room" + std::to_string(index) + ":example.org";
}

} // namespace

SCENARIO("ResolvedStateMemo answers only for the exact room, context and groups", "[database][state_memo]")
{
    GIVEN("a memo holding one room's result")
    {
        auto memo = ResolvedStateMemo{};
        memo.remember("!r:example.org", "ctx", key, entries_of(2U));

        THEN("the same key finds it")
        {
            auto const* found = memo.find("!r:example.org", "ctx", key);
            REQUIRE(found != nullptr);
            REQUIRE(found->size() == 2U);
        }

        THEN("another set of groups, context or room does not")
        {
            REQUIRE(memo.find("!r:example.org", "ctx", {"sg:a"}) == nullptr);
            REQUIRE(memo.find("!r:example.org", "ctx", {"sg:a", "sg:c"}) == nullptr);
            REQUIRE(memo.find("!r:example.org", "other", key) == nullptr);
            REQUIRE(memo.find("!s:example.org", "ctx", key) == nullptr);
        }

        WHEN("the room is forgotten")
        {
            memo.forget_room("!r:example.org");

            THEN("it is gone and its rows are returned")
            {
                REQUIRE(memo.find("!r:example.org", "ctx", key) == nullptr);
                REQUIRE(memo.rooms() == 0U);
                REQUIRE(memo.rows() == 0U);
            }
        }

        WHEN("the room remembers a later result")
        {
            memo.remember("!r:example.org", "ctx", {"sg:c", "sg:d", "sg:e"}, entries_of(1U));

            THEN("one entry remains, counted once")
            {
                REQUIRE(memo.find("!r:example.org", "ctx", key) == nullptr);
                REQUIRE(memo.rooms() == 1U);
                REQUIRE(memo.rows() == 4U);
            }
        }
    }
}

SCENARIO("ResolvedStateMemo stays within its bounds", "[database][state_memo][boundary]")
{
    GIVEN("a memo holding as many rooms as it may")
    {
        auto memo = ResolvedStateMemo{};
        for (std::size_t index = 0U; index < ResolvedStateMemo::max_rooms; ++index)
        {
            memo.remember(room_name(index), "ctx", key, entries_of(1U));
        }
        REQUIRE(memo.rooms() == ResolvedStateMemo::max_rooms);
        REQUIRE(memo.find(room_name(0U), "ctx", key) != nullptr); // now the most recently used

        WHEN("one more room is remembered")
        {
            memo.remember("!extra:example.org", "ctx", key, entries_of(1U));

            THEN("the least recently used room goes and the count stays")
            {
                REQUIRE(memo.rooms() == ResolvedStateMemo::max_rooms);
                REQUIRE(memo.find(room_name(1U), "ctx", key) == nullptr);
                REQUIRE(memo.find(room_name(0U), "ctx", key) != nullptr);
                REQUIRE(memo.find("!extra:example.org", "ctx", key) != nullptr);
            }
        }
    }

    GIVEN("a memo holding a result")
    {
        auto memo = ResolvedStateMemo{};
        memo.remember("!a:example.org", "ctx", key, entries_of(ResolvedStateMemo::max_rows - key.size() - 1U));
        REQUIRE(memo.rows() == ResolvedStateMemo::max_rows - 1U);

        WHEN("another room's result would pass the row limit")
        {
            memo.remember("!b:example.org", "ctx", key, entries_of(1U));

            THEN("the older room is evicted to make room")
            {
                REQUIRE(memo.find("!a:example.org", "ctx", key) == nullptr);
                REQUIRE(memo.find("!b:example.org", "ctx", key) != nullptr);
                REQUIRE(memo.rows() == key.size() + 1U);
            }
        }

        WHEN("a result of exactly the row limit is remembered")
        {
            memo.remember("!a:example.org", "ctx", key, entries_of(ResolvedStateMemo::max_rows - key.size()));

            THEN("it is kept")
            {
                REQUIRE(memo.rows() == ResolvedStateMemo::max_rows);
            }
        }

        WHEN("a result over the row limit is remembered for the room")
        {
            memo.remember("!a:example.org", "ctx", key, entries_of(ResolvedStateMemo::max_rows - key.size() + 1U));

            THEN("it is not kept, and the room's old result is gone with it")
            {
                REQUIRE(memo.find("!a:example.org", "ctx", key) == nullptr);
                REQUIRE(memo.rows() == 0U);
            }
        }
    }
}
