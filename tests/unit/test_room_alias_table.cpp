// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// Security audit run-4 F-03 (ADR-0581): RoomAliasTable finds an alias, lists a room's aliases and counts a creator's
// aliases through hash indexes, and keeps them right across erase (swap-and-pop), reassign and copy.

#include "merovingian/database/PersistentRoomAlias.hpp"
#include "merovingian/database/RoomAliasTable.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <string>
#include <utility>
#include <vector>

namespace
{

using merovingian::database::PersistentRoomAlias;
using merovingian::database::RoomAliasTable;

[[nodiscard]] auto alias_of(std::size_t index) -> std::string
{
    return "#a" + std::to_string(index) + ":example.org";
}

[[nodiscard]] auto room_of(std::size_t index) -> std::string
{
    return "!r" + std::to_string(index) + ":example.org";
}

[[nodiscard]] auto creator_of(std::size_t index) -> std::string
{
    return "@u" + std::to_string(index) + ":example.org";
}

[[nodiscard]] auto sorted(std::vector<std::string> values) -> std::vector<std::string>
{
    std::ranges::sort(values);
    return values;
}

// Checks every index against the rows: the table is consistent when each row is found by alias and listed under its
// room, and the per-room and per-creator counts add up to the row count.
[[nodiscard]] auto indexes_match_rows(RoomAliasTable const& table) -> bool
{
    auto rooms = std::vector<std::string>{};
    for (auto const& row : table)
    {
        auto const* const found = table.find(row.room_alias);
        if (found == nullptr || found->room_id != row.room_id)
        {
            return false;
        }
        auto const listed = table.aliases_of_room(row.room_id);
        if (std::ranges::find(listed, row.room_alias) == listed.end() ||
            listed.size() != table.count_for_room(row.room_id))
        {
            return false;
        }
        rooms.push_back(row.room_id);
    }
    auto counted = std::size_t{0U};
    std::ranges::sort(rooms);
    rooms.erase(std::ranges::unique(rooms).begin(), rooms.end());
    for (auto const& room : rooms)
    {
        counted += table.count_for_room(room);
    }
    return counted == table.size();
}

// Fills the table with `count` aliases: alias n names room n % 7 and was created by user n % 3.
[[nodiscard]] auto filled_table(std::size_t count) -> RoomAliasTable
{
    auto table = RoomAliasTable{};
    for (auto index = std::size_t{0U}; index < count; ++index)
    {
        REQUIRE(table.insert({alias_of(index), room_of(index % 7U), creator_of(index % 3U)}));
    }
    return table;
}

} // namespace

SCENARIO("A room alias table finds, lists and counts without scanning", "[f03][database][room-alias-table]")
{
    GIVEN("a table of 3000 aliases over 7 rooms and 3 creators")
    {
        auto table = filled_table(3000U);

        WHEN("one alias is looked up and one room and one creator are asked about")
        {
            THEN("each answer covers only its own key")
            {
                REQUIRE(table.size() == 3000U);
                REQUIRE(table.find(alias_of(1234U)) != nullptr);
                REQUIRE(table.find(alias_of(1234U))->room_id == room_of(1234U % 7U));
                REQUIRE(table.find("#missing:example.org") == nullptr);
                REQUIRE(table.count_for_room(room_of(0U)) == 429U);
                REQUIRE(table.aliases_of_room(room_of(0U)).size() == 429U);
                REQUIRE(table.count_for_creator(creator_of(0U)) == 1000U);
                REQUIRE(table.count_for_creator("@nobody:example.org") == 0U);
                REQUIRE(table.aliases_of_room("!none:example.org").empty());
                REQUIRE(indexes_match_rows(table));
            }
        }

        WHEN("an alias already held is inserted again")
        {
            auto const inserted = table.insert({alias_of(5U), room_of(6U), creator_of(2U)});

            THEN("the insert is refused and the held row is unchanged")
            {
                REQUIRE_FALSE(inserted);
                REQUIRE(table.size() == 3000U);
                REQUIRE(table.find(alias_of(5U))->room_id == room_of(5U));
                REQUIRE(table.count_for_creator(creator_of(2U)) == 1000U);
            }
        }

        WHEN("an alias from the front is erased, so the last row moves into its place")
        {
            auto const erased = table.erase(alias_of(0U));

            THEN("the erased alias is gone and every other alias, listing and count is right")
            {
                REQUIRE(erased);
                REQUIRE(table.size() == 2999U);
                REQUIRE(table.find(alias_of(0U)) == nullptr);
                REQUIRE(table.find(alias_of(2999U)) != nullptr);
                REQUIRE(table.find(alias_of(2999U))->room_id == room_of(2999U % 7U));
                REQUIRE(table.count_for_room(room_of(0U)) == 428U);
                REQUIRE(table.count_for_creator(creator_of(0U)) == 999U);
                REQUIRE(indexes_match_rows(table));
            }
        }

        WHEN("an alias that is not held is erased")
        {
            THEN("nothing changes")
            {
                REQUIRE_FALSE(table.erase("#missing:example.org"));
                REQUIRE(table.size() == 3000U);
            }
        }

        WHEN("every alias is erased in turn")
        {
            auto all_erased = true;
            for (auto index = std::size_t{0U}; index < 3000U; ++index)
            {
                all_erased = table.erase(alias_of(index)) && all_erased;
            }

            THEN("the table and all of its indexes are empty")
            {
                REQUIRE(all_erased);
                REQUIRE(table.empty());
                REQUIRE(table.count_for_room(room_of(0U)) == 0U);
                REQUIRE(table.count_for_creator(creator_of(0U)) == 0U);
            }
        }

        WHEN("an alias is reassigned to another room")
        {
            auto const moved = table.reassign(alias_of(0U), room_of(5U));

            THEN("it is listed under the new room only and keeps its creator")
            {
                REQUIRE(moved);
                REQUIRE(table.find(alias_of(0U))->room_id == room_of(5U));
                REQUIRE(table.find(alias_of(0U))->creator_user_id == creator_of(0U));
                REQUIRE(table.count_for_room(room_of(0U)) == 428U);
                REQUIRE(table.count_for_room(room_of(5U)) == 429U);
                REQUIRE(table.count_for_creator(creator_of(0U)) == 1000U);
                REQUIRE(indexes_match_rows(table));
            }
        }

        WHEN("an alias is reassigned to the room it already names, or one that is not held is reassigned")
        {
            THEN("the first is a no-op that succeeds and the second is refused")
            {
                REQUIRE(table.reassign(alias_of(0U), room_of(0U)));
                REQUIRE(table.count_for_room(room_of(0U)) == 429U);
                REQUIRE_FALSE(table.reassign("#missing:example.org", room_of(0U)));
            }
        }

        WHEN("the table is copied and the original is then changed")
        {
            auto copy = table;
            REQUIRE(table.erase(alias_of(1U)));
            REQUIRE(table.reassign(alias_of(2U), room_of(6U)));

            THEN("the copy keeps its own rows and its indexes agree with them")
            {
                REQUIRE(copy.size() == 3000U);
                REQUIRE(copy.find(alias_of(1U)) != nullptr);
                REQUIRE(copy.find(alias_of(2U))->room_id == room_of(2U));
                REQUIRE(copy.count_for_room(room_of(1U)) == 429U);
                REQUIRE(indexes_match_rows(copy));
                REQUIRE(indexes_match_rows(table));
            }

            AND_WHEN("the copy is erased from and the table is moved")
            {
                REQUIRE(copy.erase(alias_of(2999U)));
                auto const moved_to = RoomAliasTable{std::move(table)};

                THEN("both stay consistent")
                {
                    REQUIRE(indexes_match_rows(copy));
                    REQUIRE(indexes_match_rows(moved_to));
                    REQUIRE(moved_to.size() == 2999U);
                }
            }
        }

        WHEN("the table is cleared")
        {
            table.clear();

            THEN("nothing is found, listed or counted")
            {
                REQUIRE(table.empty());
                REQUIRE(table.find(alias_of(0U)) == nullptr);
                REQUIRE(table.aliases_of_room(room_of(0U)).empty());
                REQUIRE(table.count_for_creator(creator_of(0U)) == 0U);
            }
        }
    }

    GIVEN("a table holding a legacy alias with no creator")
    {
        auto table = RoomAliasTable{};
        REQUIRE(table.insert({"#legacy:example.org", "!r:example.org", ""}));

        WHEN("the creator count of the empty creator is read, then the alias is erased")
        {
            auto const counted = table.count_for_creator("");
            auto const erased = table.erase("#legacy:example.org");

            THEN("no creator is charged for it")
            {
                REQUIRE(counted == 0U);
                REQUIRE(erased);
                REQUIRE(table.empty());
            }
        }
    }

    GIVEN("a table with two aliases of one room")
    {
        auto table = RoomAliasTable{};
        REQUIRE(table.insert({"#b:example.org", "!r:example.org", "@u:example.org"}));
        REQUIRE(table.insert({"#a:example.org", "!r:example.org", "@u:example.org"}));

        WHEN("the room's aliases are listed")
        {
            THEN("both are returned")
            {
                REQUIRE(sorted(table.aliases_of_room("!r:example.org")) ==
                        std::vector<std::string>{"#a:example.org", "#b:example.org"});
            }
        }
    }
}
