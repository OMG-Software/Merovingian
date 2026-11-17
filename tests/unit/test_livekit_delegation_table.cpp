// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The in-memory LiveKit delegations table (migration 004, ADR-0832): what it refuses, the lookups by delay ID and by
// key, the per-user count, insertion order, and that every erase keeps the indexes right.
#include "merovingian/database/LiveKitDelegationRowText.hpp"
#include "merovingian/database/LiveKitDelegationTable.hpp"
#include "merovingian/database/PersistentLiveKitDelegation.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>

namespace
{

namespace db = merovingian::database;
using db::PersistentLiveKitDelegation;

constexpr auto alice = std::string_view{"@alice:example.org"};
constexpr auto bob = std::string_view{"@bob:example.org"};

[[nodiscard]] auto delegation(std::string delay_id, std::string_view user = alice, std::string_view member = "member-1")
    -> PersistentLiveKitDelegation
{
    return {std::move(delay_id), std::string{user}, "!room:example.org", "slot-1", std::string{member}, 1'000U};
}

} // namespace

SCENARIO("The delegations table finds a row by delay ID and by key",
         "[database][livekit-delegations][delegation-table]")
{
    GIVEN("a table holding two rows of one user and one of another")
    {
        auto table = db::LiveKitDelegationTable{};
        REQUIRE(table.insert(delegation("d-1", alice, "member-1")));
        REQUIRE(table.insert(delegation("d-2", alice, "member-2")));
        REQUIRE(table.insert(delegation("d-3", bob, "member-1")));

        WHEN("the rows are looked up")
        {
            THEN("each lookup answers the row, the count is per user and the rows keep insertion order")
            {
                REQUIRE(table.size() == 3U);
                REQUIRE(table.find("d-2") != nullptr);
                REQUIRE(table.find("d-2")->member_id == "member-2");
                REQUIRE(table.find("d-2")->created_ms == 1'000U);
                REQUIRE(table.find("d-none") == nullptr);
                REQUIRE(table.find_by_key(alice, "!room:example.org", "slot-1", "member-2") == table.find("d-2"));
                REQUIRE(table.find_by_key(bob, "!room:example.org", "slot-1", "member-1") == table.find("d-3"));
                REQUIRE(table.find_by_key(bob, "!room:example.org", "slot-1", "member-2") == nullptr);
                REQUIRE(table.find_by_key(alice, "!other:example.org", "slot-1", "member-1") == nullptr);
                REQUIRE(table.find_by_key(alice, "!room:example.org", "slot-2", "member-1") == nullptr);
                REQUIRE(table.count_of_user(alice) == 2U);
                REQUIRE(table.count_of_user(bob) == 1U);
                REQUIRE(table.count_of_user("@nobody:example.org") == 0U);
                REQUIRE(table.rows().size() == 3U);
                REQUIRE(table.rows()[0].delay_id == "d-1");
                REQUIRE(table.rows()[1].delay_id == "d-2");
                REQUIRE(table.rows()[2].delay_id == "d-3");
            }
        }

        WHEN("the key parts are shifted between fields so the joined text would be the same")
        {
            THEN("a key that differs in one part finds nothing")
            {
                REQUIRE(table.find_by_key("@alice:example.org!room:example.org", "slot-1", "member-1", "") == nullptr);
                REQUIRE(table.find_by_key(alice, "!room:example.orgslot-1", "member-1", "") == nullptr);
            }
        }
    }
}

SCENARIO("The delegations table refuses a row that is not storable or that duplicates a delay ID or a key",
         "[database][livekit-delegations][delegation-table]")
{
    GIVEN("a table holding one row")
    {
        auto table = db::LiveKitDelegationTable{};
        REQUIRE(table.insert(delegation("d-1")));

        WHEN("rows are inserted that break a rule")
        {
            auto const same_delay_id = table.insert(delegation("d-1", bob));
            auto const same_key = table.insert(delegation("d-other"));
            auto empty_delay_id = delegation("");
            auto empty_user = delegation("d-2");
            empty_user.user_id.clear();
            auto empty_room = delegation("d-3");
            empty_room.room_id.clear();
            auto empty_slot = delegation("d-4");
            empty_slot.slot_id.clear();
            auto empty_member = delegation("d-5");
            empty_member.member_id.clear();
            auto long_delay_id = delegation(std::string(db::max_livekit_delegation_delay_id_bytes + 1U, 'd'));
            auto long_user = delegation("d-6");
            long_user.user_id = std::string(db::max_livekit_delegation_field_bytes + 1U, 'u');
            auto long_room = delegation("d-7");
            long_room.room_id = std::string(db::max_livekit_delegation_field_bytes + 1U, 'r');
            auto long_slot = delegation("d-8");
            long_slot.slot_id = std::string(db::max_livekit_delegation_field_bytes + 1U, 's');
            auto long_member = delegation("d-9");
            long_member.member_id = std::string(db::max_livekit_delegation_field_bytes + 1U, 'm');
            auto nul_slot = delegation("d-10");
            nul_slot.slot_id = std::string{"a\0b", 3U};

            THEN("each is refused and the table is unchanged")
            {
                REQUIRE_FALSE(same_delay_id);
                REQUIRE_FALSE(same_key);
                REQUIRE_FALSE(table.insert(empty_delay_id));
                REQUIRE_FALSE(table.insert(empty_user));
                REQUIRE_FALSE(table.insert(empty_room));
                REQUIRE_FALSE(table.insert(empty_slot));
                REQUIRE_FALSE(table.insert(empty_member));
                REQUIRE_FALSE(table.insert(long_delay_id));
                REQUIRE_FALSE(table.insert(long_user));
                REQUIRE_FALSE(table.insert(long_room));
                REQUIRE_FALSE(table.insert(long_slot));
                REQUIRE_FALSE(table.insert(long_member));
                REQUIRE_FALSE(table.insert(nul_slot));
                REQUIRE(table.size() == 1U);
                REQUIRE(table.count_of_user(alice) == 1U);
                REQUIRE(table.count_of_user(bob) == 0U);
            }
        }

        WHEN("rows exactly at the caps are inserted")
        {
            auto at_cap = delegation(std::string(db::max_livekit_delegation_delay_id_bytes, 'd'));
            at_cap.user_id = std::string(db::max_livekit_delegation_field_bytes, 'u');
            at_cap.room_id = std::string(db::max_livekit_delegation_field_bytes, 'r');
            at_cap.slot_id = std::string(db::max_livekit_delegation_field_bytes, 's');
            at_cap.member_id = std::string(db::max_livekit_delegation_field_bytes, 'm');

            THEN("the row is stored")
            {
                REQUIRE(table.insert(at_cap));
                REQUIRE(table.size() == 2U);
            }
        }
    }
}

SCENARIO("Erasing from the delegations table keeps every index right",
         "[database][livekit-delegations][delegation-table]")
{
    GIVEN("a table holding four rows of two users")
    {
        auto table = db::LiveKitDelegationTable{};
        REQUIRE(table.insert(delegation("d-1", alice, "member-1")));
        REQUIRE(table.insert(delegation("d-2", bob, "member-1")));
        REQUIRE(table.insert(delegation("d-3", alice, "member-2")));
        REQUIRE(table.insert(delegation("d-4", bob, "member-2")));

        WHEN("a row is erased by delay ID")
        {
            auto const erased = table.erase("d-2");
            auto const again = table.erase("d-2");

            THEN("the later rows are still found by both lookups, in order, and the count dropped")
            {
                REQUIRE(erased);
                REQUIRE_FALSE(again);
                REQUIRE(table.size() == 3U);
                REQUIRE(table.find("d-2") == nullptr);
                REQUIRE(table.find("d-3")->member_id == "member-2");
                REQUIRE(table.find_by_key(bob, "!room:example.org", "slot-1", "member-2") == table.find("d-4"));
                REQUIRE(table.find_by_key(bob, "!room:example.org", "slot-1", "member-1") == nullptr);
                REQUIRE(table.count_of_user(bob) == 1U);
                REQUIRE(table.count_of_user(alice) == 2U);
                REQUIRE(table.rows()[1].delay_id == "d-3");
            }

            AND_THEN("the erased key and delay ID can be inserted again")
            {
                REQUIRE(table.insert(delegation("d-2", bob, "member-1")));
                REQUIRE(table.rows().back().delay_id == "d-2");
            }
        }

        WHEN("a row is erased by key")
        {
            auto const erased = table.erase_key(alice, "!room:example.org", "slot-1", "member-1");
            auto const again = table.erase_key(alice, "!room:example.org", "slot-1", "member-1");

            THEN("it is gone by delay ID too, and the rest are unchanged")
            {
                REQUIRE(erased);
                REQUIRE_FALSE(again);
                REQUIRE(table.find("d-1") == nullptr);
                REQUIRE(table.size() == 3U);
                REQUIRE(table.count_of_user(alice) == 1U);
                REQUIRE(table.find("d-4") != nullptr);
            }
        }

        WHEN("every row of one user is erased")
        {
            auto const removed = table.erase_user(alice);
            auto const none = table.erase_user("@nobody:example.org");

            THEN("the other user's rows remain and the count is returned")
            {
                REQUIRE(removed == 2U);
                REQUIRE(none == 0U);
                REQUIRE(table.size() == 2U);
                REQUIRE(table.count_of_user(alice) == 0U);
                REQUIRE(table.find("d-1") == nullptr);
                REQUIRE(table.find("d-3") == nullptr);
                REQUIRE(table.find("d-4")->user_id == std::string{bob});
            }
        }

        WHEN("the table is cleared and a copy is taken before")
        {
            auto const copy = table;
            table.clear();

            THEN("the table is empty and the copy still answers every lookup")
            {
                REQUIRE(table.size() == 0U);
                REQUIRE(table.find("d-1") == nullptr);
                REQUIRE(table.count_of_user(alice) == 0U);
                REQUIRE(copy.size() == 4U);
                REQUIRE(copy.find_by_key(alice, "!room:example.org", "slot-1", "member-2") == copy.find("d-3"));
            }
        }
    }
}

SCENARIO("A stored delegation row is read strictly", "[database][livekit-delegations][delegation-table]")
{
    GIVEN("the six columns of a valid row")
    {
        auto const valid = std::array<std::string, db::livekit_delegation_row_columns>{
            "d-1", std::string{alice}, "!room:example.org", "slot-1", "member-1", "123456789"};

        WHEN("it is read")
        {
            auto const parsed = db::parse_livekit_delegation_row(valid);

            THEN("every field is carried over")
            {
                REQUIRE(parsed.has_value());
                REQUIRE(parsed->delay_id == "d-1");
                REQUIRE(parsed->user_id == std::string{alice});
                REQUIRE(parsed->room_id == "!room:example.org");
                REQUIRE(parsed->slot_id == "slot-1");
                REQUIRE(parsed->member_id == "member-1");
                REQUIRE(parsed->created_ms == 123'456'789U);
            }
        }

        WHEN("one column is damaged")
        {
            auto const column = GENERATE(std::size_t{0U}, std::size_t{1U}, std::size_t{2U}, std::size_t{3U},
                                         std::size_t{4U}, std::size_t{5U});
            auto damaged = valid;
            damaged[column] = "";

            THEN("an empty column is not read")
            {
                REQUIRE_FALSE(db::parse_livekit_delegation_row(damaged).has_value());
            }
        }

        WHEN("created_ms is not exactly decimal digits that fit 64 bits")
        {
            auto const bad =
                GENERATE(std::string{"abc"}, std::string{"-5"}, std::string{" 5"}, std::string{"5 "},
                         std::string{"1.5"}, std::string{"123456789012345678901"}, std::string{"18446744073709551616"});
            auto damaged = valid;
            damaged[5] = bad;

            THEN("the row is not read")
            {
                INFO(bad);
                REQUIRE_FALSE(db::parse_livekit_delegation_row(damaged).has_value());
            }
        }

        WHEN("created_ms is the largest 64-bit value, or a field is over its cap, or there are too few columns")
        {
            auto largest = valid;
            largest[5] = "18446744073709551615";
            auto over_long = valid;
            over_long[3] = std::string(db::max_livekit_delegation_field_bytes + 1U, 's');
            auto over_long_id = valid;
            over_long_id[0] = std::string(db::max_livekit_delegation_delay_id_bytes + 1U, 'd');
            auto const few = std::array<std::string, 3U>{"d-1", std::string{alice}, "!room:example.org"};

            THEN("the largest value is read and the others are not")
            {
                REQUIRE(db::parse_livekit_delegation_row(largest).has_value());
                REQUIRE_FALSE(db::parse_livekit_delegation_row(over_long).has_value());
                REQUIRE_FALSE(db::parse_livekit_delegation_row(over_long_id).has_value());
                REQUIRE_FALSE(db::parse_livekit_delegation_row(few).has_value());
            }
        }
    }
}
