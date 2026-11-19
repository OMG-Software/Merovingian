// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// `select_sticky_for_sync` (ADR-0855): which sticky events one room's sync response carries.

#include "merovingian/sync/StickyCandidate.hpp"
#include "merovingian/sync/StickyChoice.hpp"
#include "merovingian/sync/StickySelection.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

namespace
{

using merovingian::sync::select_sticky_for_sync;
using merovingian::sync::StickyCandidate;

constexpr auto no_limit = std::numeric_limits<std::size_t>::max();

[[nodiscard]] auto candidates() -> std::vector<StickyCandidate>
{
    // Listed out of order on purpose: the selection orders them.
    return {
        {"$c", "@alice:example.org", 30U},
        {"$a", "@alice:example.org", 10U},
        {"$d", "@mallory:example.org", 40U},
        {"$b", "@bob:example.org", 20U},
    };
}

} // namespace

SCENARIO("sticky events are chosen oldest first", "[sync][sticky-events]")
{
    GIVEN("four candidates")
    {
        WHEN("nothing is excluded")
        {
            auto const choice = select_sticky_for_sync(candidates(), 100U, std::nullopt, {}, {}, no_limit);
            THEN("all are chosen, oldest first")
            {
                REQUIRE(choice.event_ids == std::vector<std::string>{"$a", "$b", "$c", "$d"});
                REQUIRE_FALSE(choice.more);
            }
        }

        WHEN("the upper bound is 30")
        {
            auto const choice = select_sticky_for_sync(candidates(), 30U, std::nullopt, {}, {}, no_limit);
            THEN("a later event is left out and the bound itself is kept")
            {
                REQUIRE(choice.event_ids == std::vector<std::string>{"$a", "$b", "$c"});
            }
        }

        WHEN("the position is 20")
        {
            auto const choice = select_sticky_for_sync(candidates(), 100U, std::uint64_t{20U}, {}, {}, no_limit);
            THEN("only events after it are chosen")
            {
                REQUIRE(choice.event_ids == std::vector<std::string>{"$c", "$d"});
            }
        }
    }
}

SCENARIO("a sticky event is left out when it is excluded or its sender is ignored", "[sync][sticky-events]")
{
    GIVEN("four candidates")
    {
        WHEN("one is in the timeline and one sender is ignored")
        {
            auto const choice = select_sticky_for_sync(candidates(), 100U, std::nullopt, {"@mallory:example.org"},
                                                       std::unordered_set<std::string>{"$b"}, no_limit);
            THEN("neither is chosen")
            {
                REQUIRE(choice.event_ids == std::vector<std::string>{"$a", "$c"});
            }
        }

        WHEN("there are none")
        {
            auto const choice = select_sticky_for_sync({}, 100U, std::nullopt, {}, {}, no_limit);
            THEN("nothing is chosen")
            {
                REQUIRE(choice.event_ids.empty());
                REQUIRE_FALSE(choice.more);
            }
        }
    }
}

SCENARIO("a limit keeps the oldest and says more remain", "[sync][sticky-events]")
{
    GIVEN("four candidates")
    {
        WHEN("the limit is two")
        {
            auto const choice = select_sticky_for_sync(candidates(), 100U, std::nullopt, {}, {}, 2U);
            THEN("the two oldest are chosen and more remain")
            {
                REQUIRE(choice.event_ids == std::vector<std::string>{"$a", "$b"});
                REQUIRE(choice.more);
            }
        }

        WHEN("the limit equals the eligible count")
        {
            auto const choice = select_sticky_for_sync(candidates(), 100U, std::nullopt, {}, {}, 4U);
            THEN("nothing remains")
            {
                REQUIRE(choice.event_ids.size() == 4U);
                REQUIRE_FALSE(choice.more);
            }
        }
    }
}
