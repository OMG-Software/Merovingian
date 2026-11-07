// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Spec: Matrix Client-Server API v1.19, Filtering
// URL:  ../../docs/matrix-v1.19-spec/client-server-api.md#filtering
//
// `types` and `not_types`: "A `*` can be used as a wildcard to match any sequence of characters."

#include "merovingian/sync/EventTypeFilter.hpp"
#include "merovingian/sync/SyncFilter.hpp"
#include "merovingian/sync/type_pattern.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

using merovingian::sync::type_pattern_matches;

SCENARIO("A type pattern's star stands for any run of characters wherever it sits", "[sync][filter][type_pattern]")
{
    GIVEN("patterns with a star in the middle, at the start and at the end")
    {
        WHEN("event types are matched against them")
        {
            THEN("the star matches any run, the empty run included")
            {
                REQUIRE(type_pattern_matches("m.*.message", "m.room.message"));
                REQUIRE(type_pattern_matches("m.*.message", "m..message"));
                REQUIRE(type_pattern_matches("m.*.message", "m.a.b.message"));
                REQUIRE(type_pattern_matches("*.message", "m.room.message"));
                REQUIRE(type_pattern_matches("m.room.*", "m.room.message"));
                REQUIRE(type_pattern_matches("m.room.*", "m.room."));
                REQUIRE(type_pattern_matches("*", "m.room.message"));
                REQUIRE(type_pattern_matches("*", ""));
                REQUIRE(type_pattern_matches("**", "anything"));
                REQUIRE(type_pattern_matches("a*b*c", "abc"));
                REQUIRE(type_pattern_matches("a*b*c", "aXXbYYc"));
                REQUIRE(type_pattern_matches("*a*b*", "xxaxxbxx"));
            }
            THEN("a type the pattern does not describe is rejected")
            {
                REQUIRE_FALSE(type_pattern_matches("m.*.message", "m.room.name"));
                REQUIRE_FALSE(type_pattern_matches("m.*.message", "m.message"));
                REQUIRE_FALSE(type_pattern_matches("*.message", "m.room.messages"));
                REQUIRE_FALSE(type_pattern_matches("m.room.*", "m.roo"));
                REQUIRE_FALSE(type_pattern_matches("a*b*c", "acb"));
                REQUIRE_FALSE(type_pattern_matches("a*b*c", "ab"));
                REQUIRE_FALSE(type_pattern_matches("*a*b*", "xxbxxaxx"));
            }
            THEN("the head and the tail of a pattern never overlap in the type")
            {
                REQUIRE_FALSE(type_pattern_matches("ab*ba", "aba"));
                REQUIRE(type_pattern_matches("ab*ba", "abba"));
                REQUIRE_FALSE(type_pattern_matches("a*a", "a"));
                REQUIRE(type_pattern_matches("a*a", "aa"));
            }
            THEN("a pattern without a star is an exact match")
            {
                REQUIRE(type_pattern_matches("m.room.message", "m.room.message"));
                REQUIRE_FALSE(type_pattern_matches("m.room.message", "m.room.message2"));
                REQUIRE_FALSE(type_pattern_matches("", "m"));
                REQUIRE(type_pattern_matches("", ""));
            }
        }
    }
}

SCENARIO("A pathological pattern is judged without backtracking", "[sync][filter][type_pattern]")
{
    GIVEN("a pattern of many a-runs followed by a letter the type lacks, and a long type of a's")
    {
        auto pattern = std::string{"*"};
        for (auto i = 0; i < 2000; ++i)
        {
            pattern += "a*";
        }
        pattern += "b*";
        auto const type = std::string(4000, 'a');

        WHEN("the pattern is matched")
        {
            auto const matched = type_pattern_matches(pattern, type);

            THEN("it is rejected, quickly enough that the test finishes")
            {
                // A backtracking matcher takes exponential time here; this one scans the type once.
                REQUIRE_FALSE(matched);
            }
        }
    }
}

SCENARIO("Event types are filtered by a wildcard anywhere in types and not_types", "[sync][filter][type_pattern]")
{
    GIVEN("a filter with a mid-pattern wildcard in types and one in not_types")
    {
        auto filter = merovingian::sync::EventTypeFilter{};
        filter.types = {"m.*.message", "m.room.*"};
        filter.not_types = {"m.room.*.secret"};

        WHEN("events are judged")
        {
            THEN("included types pass and excluded ones are dropped even when included")
            {
                REQUIRE(merovingian::sync::event_passes_filter(filter, "m.room.message", "@a:x"));
                REQUIRE(merovingian::sync::event_passes_filter(filter, "m.room.name", "@a:x"));
                REQUIRE_FALSE(merovingian::sync::event_passes_filter(filter, "m.room.x.secret", "@a:x"));
                REQUIRE_FALSE(merovingian::sync::event_passes_filter(filter, "m.reaction", "@a:x"));
            }
        }
    }
}
