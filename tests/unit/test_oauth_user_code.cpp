// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// Plan P11 (ADR-0805): the device authorization grant's user code. Eight characters from twenty consonants, drawn by
// rejection sampling; a typed code is read in any case and with dashes, spaces, dots or underscores, and anything else
// is refused whole.

#include "merovingian/oauth/UserCode.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace
{

using merovingian::oauth::display_user_code;
using merovingian::oauth::normalise_user_code;
using merovingian::oauth::user_code_alphabet;
using merovingian::oauth::user_code_from_bytes;
using merovingian::oauth::user_code_length;

[[nodiscard]] auto from(std::vector<std::uint8_t> const& bytes) -> std::optional<std::string>
{
    return user_code_from_bytes(std::span<std::uint8_t const>{bytes});
}

} // namespace

SCENARIO("A user code is eight alphabet characters, each byte below 240 giving one", "[oauth][user-code]")
{
    GIVEN("the alphabet")
    {
        THEN("it holds twenty distinct upper-case consonants and no vowel or digit")
        {
            REQUIRE(user_code_alphabet.size() == 20U);
            for (auto const c : user_code_alphabet)
            {
                REQUIRE(c >= 'A');
                REQUIRE(c <= 'Z');
                REQUIRE(std::string_view{"AEIOUY"}.find(c) == std::string_view::npos);
                REQUIRE(user_code_alphabet.find(c) == user_code_alphabet.rfind(c));
            }
        }
    }

    GIVEN("bytes whose values are the alphabet positions")
    {
        WHEN("a code is drawn from 0 to 7")
        {
            auto const code = from({0U, 1U, 2U, 3U, 4U, 5U, 6U, 7U});

            THEN("it is the first eight characters")
            {
                REQUIRE(code == std::optional<std::string>{"BCDFGHJK"});
            }
        }

        WHEN("a code is drawn from bytes at the top of the accepted range")
        {
            auto const code = from({20U, 39U, 219U, 239U, 0U, 19U, 220U, 238U});

            THEN("each byte gives the character at its value modulo twenty")
            {
                REQUIRE(code.has_value());
                REQUIRE(code->size() == user_code_length);
                REQUIRE((*code)[0] == 'B');
                REQUIRE((*code)[1] == 'Z');
                REQUIRE((*code)[2] == 'Z');
                REQUIRE((*code)[3] == 'Z');
                REQUIRE((*code)[4] == 'B');
                REQUIRE((*code)[5] == 'Z');
                REQUIRE((*code)[6] == 'B');
                REQUIRE((*code)[7] == 'X');
            }
        }
    }

    GIVEN("bytes of 240 and over between accepted ones")
    {
        WHEN("a code is drawn")
        {
            auto const code = from({240U, 0U, 255U, 1U, 2U, 3U, 250U, 4U, 5U, 6U, 7U});

            THEN("those bytes are skipped, so no character is more likely than another")
            {
                REQUIRE(code == std::optional<std::string>{"BCDFGHJK"});
            }
        }
    }

    GIVEN("too few bytes below 240")
    {
        WHEN("a code is drawn from seven usable bytes and many rejected ones")
        {
            auto const code = from({0U, 1U, 2U, 3U, 4U, 5U, 6U, 240U, 241U, 255U});
            auto const empty = from({});

            THEN("no code is made")
            {
                REQUIRE_FALSE(code.has_value());
                REQUIRE_FALSE(empty.has_value());
            }
        }
    }
}

SCENARIO("A typed user code is read in any case, with separators skipped, and refused whole otherwise",
         "[oauth][user-code][security]")
{
    GIVEN("the ways a user may type the code BCDFGHJK")
    {
        WHEN("each is read")
        {
            THEN("each is the stored form")
            {
                for (auto const typed :
                     {"BCDFGHJK", "bcdfghjk", "BCDF-GHJK", "bcdf ghjk", " BcDf.Gh_Jk ", "B-C-D-F-G-H-J-K"})
                {
                    REQUIRE(normalise_user_code(typed) == std::optional<std::string>{"BCDFGHJK"});
                }
            }
        }
    }

    GIVEN("text that is not a code")
    {
        WHEN("each is read")
        {
            THEN("each is refused")
            {
                // A vowel, a digit, a letter the alphabet lacks, seven and nine characters, a control byte, a
                // non-ASCII letter, a plus sign, nothing at all, and only separators.
                for (auto const typed : {"BCDFGHJA", "BCDFGHJ1", "BCDFGHJY", "BCDFGHJ", "BCDFGHJKL", "BCDF\tGHJK",
                                         "BCDF\xC3\x89GHJK", "BCDF+GHJK", "", "----"})
                {
                    REQUIRE_FALSE(normalise_user_code(typed).has_value());
                }
            }
        }
    }

    GIVEN("a right code padded past the length cap")
    {
        auto padded = std::string(merovingian::oauth::max_typed_user_code_bytes - 8U, ' ');
        padded.append("BCDFGHJK");
        auto over = padded;
        over.push_back(' ');

        WHEN("both are read")
        {
            THEN("the one at the cap is read and the one over it refused, never shortened")
            {
                REQUIRE(padded.size() == merovingian::oauth::max_typed_user_code_bytes);
                REQUIRE(normalise_user_code(padded) == std::optional<std::string>{"BCDFGHJK"});
                REQUIRE_FALSE(normalise_user_code(over).has_value());
            }
        }
    }
}

SCENARIO("A stored user code is shown as two groups of four", "[oauth][user-code]")
{
    GIVEN("a stored code and text that is not one")
    {
        WHEN("each is shown")
        {
            THEN("the code gets a dash in the middle and the other text is unchanged")
            {
                REQUIRE(display_user_code("BCDFGHJK") == "BCDF-GHJK");
                REQUIRE(display_user_code("abc") == "abc");
                REQUIRE(display_user_code("BCDFGHJKL") == "BCDFGHJKL");
            }
        }
    }
}
