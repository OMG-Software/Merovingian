// SPDX-License-Identifier: GPL-3.0-or-later
//
// FoldedSubstringMatcher: the one linear-time, ASCII-case-insensitive substring search behind POST /search,
// POST /publicRooms and POST /user_directory/search (security audit run 2, F-28, F-29, F-34; ADR-0330).
// The Matrix v1.19 spec gives the three search terms no length limit and no matching algorithm; what is
// tested here is the project's rule that a client's term and text never cost more than a pass over the text.

#include "merovingian/core/folded_substring.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <string>
#include <string_view>

using merovingian::core::FoldedSubstringMatcher;

SCENARIO("a term is found whatever the case of the text and the term", "[folded-substring][search]")
{
    GIVEN("a matcher for a mixed-case term")
    {
        auto matcher = FoldedSubstringMatcher{"HeLLo"};

        WHEN("it searches text holding the term in other cases")
        {
            THEN("each is found")
            {
                REQUIRE(matcher.contains("say hello world"));
                REQUIRE(matcher.contains("HELLO"));
                REQUIRE(matcher.contains("hElLo"));
            }
        }

        WHEN("it searches text without the term")
        {
            THEN("none is found")
            {
                REQUIRE_FALSE(matcher.contains("hell o"));
                REQUIRE_FALSE(matcher.contains("hell"));
                REQUIRE_FALSE(matcher.contains(""));
            }
        }
    }

    GIVEN("a term with bytes outside ASCII")
    {
        auto matcher = FoldedSubstringMatcher{"caf\xC3\xA9"};

        WHEN("it searches text with the same bytes")
        {
            THEN("they match byte for byte, and a different byte sequence does not")
            {
                REQUIRE(matcher.contains("un CAF\xC3\xA9 noir"));
                REQUIRE_FALSE(matcher.contains("un CAF\xC3\x89 noir"));
            }
        }
    }
}

SCENARIO("an empty term is held by every text and counted in none", "[folded-substring][search]")
{
    GIVEN("a matcher for the empty term")
    {
        auto matcher = FoldedSubstringMatcher{""};

        WHEN("it searches")
        {
            THEN("it is contained, and has no occurrences")
            {
                REQUIRE(matcher.contains("anything"));
                REQUIRE(matcher.count_non_overlapping("anything") == 0U);
            }
        }
    }
}

SCENARIO("occurrences are counted left to right without overlapping", "[folded-substring][search]")
{
    GIVEN("a matcher for a term that overlaps itself")
    {
        auto matcher = FoldedSubstringMatcher{"aa"};

        WHEN("it counts runs of the letter")
        {
            THEN("each occurrence uses its own bytes")
            {
                REQUIRE(matcher.count_non_overlapping("aaaa") == 2U);
                REQUIRE(matcher.count_non_overlapping("aaa") == 1U);
                REQUIRE(matcher.count_non_overlapping("AaBaa") == 2U);
                REQUIRE(matcher.count_non_overlapping("a") == 0U);
            }
        }
    }

    GIVEN("a matcher for a term whose prefix repeats inside it")
    {
        auto matcher = FoldedSubstringMatcher{"abab"};

        WHEN("it searches a text where the failure table must be followed")
        {
            THEN("the occurrence is found after the false start")
            {
                REQUIRE(matcher.contains("abaabab"));
                REQUIRE(matcher.count_non_overlapping("ababab") == 1U);
                REQUIRE(matcher.count_non_overlapping("abababab") == 2U);
            }
        }
    }
}

// F-28, F-29, F-34: std::search and std::string_view::find restart the comparison at every offset, so a
// text of a's and a term of a's ending in b cost text * term comparisons. The matcher's steps are bounded
// by twice the bytes of text it was given, for the same adversarial input.
SCENARIO("a term built to nearly match costs no more than a pass over the text", "[folded-substring][search][security]")
{
    GIVEN("a 60000 byte text of a's and a 30000 byte term of a's ending in b")
    {
        auto const text = std::string(60000U, 'a');
        auto const term = std::string(30000U, 'a') + "b";
        auto matcher = FoldedSubstringMatcher{term};

        WHEN("the matcher searches the text")
        {
            auto const found = matcher.contains(text);

            THEN("nothing is found, in at most two steps per byte of text")
            {
                REQUIRE_FALSE(found);
                REQUIRE(matcher.steps() <= 2U * text.size());
            }
        }

        WHEN("the matcher counts occurrences in the text")
        {
            auto const count = matcher.count_non_overlapping(text);

            THEN("there are none, in at most two steps per byte of text")
            {
                REQUIRE(count == 0U);
                REQUIRE(matcher.steps() <= 2U * text.size());
            }
        }
    }

    GIVEN("a term whose failure table is as deep as it can be")
    {
        auto const term = std::string(2000U, 'a') + "b";
        auto matcher = FoldedSubstringMatcher{term};
        auto text = std::string{};
        for (auto i = std::size_t{0U}; i < 40U; ++i)
        {
            text += std::string(1999U, 'a') + "c";
        }

        WHEN("the matcher searches a text that keeps almost matching")
        {
            auto const found = matcher.contains(text);

            THEN("the steps stay within twice the text however often it almost matches")
            {
                REQUIRE_FALSE(found);
                REQUIRE(matcher.steps() <= 2U * text.size());
            }
        }
    }

    GIVEN("a matcher that has searched several texts")
    {
        auto matcher = FoldedSubstringMatcher{"needle"};
        auto const first = std::string(1000U, 'x');
        auto const second = std::string(500U, 'n');

        WHEN("it has searched both")
        {
            REQUIRE_FALSE(matcher.contains(first));
            REQUIRE_FALSE(matcher.contains(second));

            THEN("its steps total at most twice the bytes of both texts")
            {
                REQUIRE(matcher.steps() <= 2U * (first.size() + second.size()));
            }
        }
    }
}

SCENARIO("the search term cap is one constant shared by the three endpoints", "[folded-substring][search]")
{
    GIVEN("the cap")
    {
        WHEN("it is read")
        {
            THEN("it leaves room for any real search and stays far below the request body cap")
            {
                REQUIRE(merovingian::core::max_search_term_bytes >= 256U);
                REQUIRE(merovingian::core::max_search_term_bytes <= 4096U);
            }
        }
    }
}
