// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The `GET /mutual_rooms` pagination token (audit gate-l, resource exhaustion): the offset travels in the token with a
// keyed check over caller, target user and offset, so verifying one costs a single hash.
#include "merovingian/homeserver/MutualRoomsToken.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace
{

using merovingian::homeserver::decode_mutual_rooms_token;
using merovingian::homeserver::encode_mutual_rooms_token;

[[nodiscard]] auto key_of(std::uint8_t fill) -> std::vector<std::uint8_t>
{
    return std::vector<std::uint8_t>(32U, fill);
}

} // namespace

SCENARIO("A mutual rooms token round-trips the offset it was issued for", "[mutual-rooms][token]")
{
    GIVEN("a key, a caller and a target user")
    {
        auto const key = key_of(7U);

        WHEN("tokens are issued for several offsets, one far beyond any room count")
        {
            THEN("each decodes to exactly its own offset")
            {
                for (auto const offset : {std::size_t{0U}, std::size_t{20U}, std::size_t{1001U}, std::size_t{5000000U}})
                {
                    auto const token = encode_mutual_rooms_token("@a:example.org", "@b:example.org", offset, key);
                    REQUIRE(token.has_value());
                    REQUIRE(decode_mutual_rooms_token("@a:example.org", "@b:example.org", *token, key) == offset);
                }
            }
        }

        WHEN("two offsets are issued")
        {
            auto const first = encode_mutual_rooms_token("@a:example.org", "@b:example.org", 1U, key);
            auto const second = encode_mutual_rooms_token("@a:example.org", "@b:example.org", 2U, key);

            THEN("the tokens differ")
            {
                REQUIRE(first.has_value());
                REQUIRE(second.has_value());
                REQUIRE(*first != *second);
            }
        }
    }
}

SCENARIO("A mutual rooms token that was not issued for this pair, key and offset is refused", "[mutual-rooms][token]")
{
    GIVEN("a token issued to alice about bob at offset 20")
    {
        auto const key = key_of(7U);
        auto const token = encode_mutual_rooms_token("@alice:example.org", "@bob:example.org", 20U, key);
        REQUIRE(token.has_value());

        WHEN("it is presented by another caller, for another target, or under another key")
        {
            THEN("each is refused")
            {
                REQUIRE_FALSE(
                    decode_mutual_rooms_token("@carol:example.org", "@bob:example.org", *token, key).has_value());
                REQUIRE_FALSE(
                    decode_mutual_rooms_token("@alice:example.org", "@carol:example.org", *token, key).has_value());
                REQUIRE_FALSE(decode_mutual_rooms_token("@alice:example.org", "@bob:example.org", *token, key_of(8U))
                                  .has_value());
            }
        }

        WHEN("its offset is changed, its check is changed, or it is cut short")
        {
            auto const dot = token->find('.');
            REQUIRE(dot != std::string::npos);
            auto const forged_offset = "21" + token->substr(dot);
            auto flipped = *token;
            flipped.back() = flipped.back() == '0' ? '1' : '0';

            THEN("each is refused")
            {
                REQUIRE_FALSE(decode_mutual_rooms_token("@alice:example.org", "@bob:example.org", forged_offset, key)
                                  .has_value());
                REQUIRE_FALSE(
                    decode_mutual_rooms_token("@alice:example.org", "@bob:example.org", flipped, key).has_value());
                REQUIRE_FALSE(decode_mutual_rooms_token("@alice:example.org", "@bob:example.org",
                                                        token->substr(0U, token->size() - 1U), key)
                                  .has_value());
            }
        }

        WHEN("junk is presented")
        {
            THEN("each is refused")
            {
                for (auto const* junk : {"", "zzz", ".", "5.", ".abc", "-1.abc", "99999999999999999999999.abc", "20",
                                         "20.20.20", "+20.abc"})
                {
                    REQUIRE_FALSE(
                        decode_mutual_rooms_token("@alice:example.org", "@bob:example.org", junk, key).has_value());
                }
            }
        }

        WHEN("no key is configured")
        {
            THEN("nothing is issued and nothing is accepted")
            {
                REQUIRE_FALSE(encode_mutual_rooms_token("@alice:example.org", "@bob:example.org", 20U, {}).has_value());
                REQUIRE_FALSE(
                    decode_mutual_rooms_token("@alice:example.org", "@bob:example.org", *token, {}).has_value());
            }
        }
    }
}
