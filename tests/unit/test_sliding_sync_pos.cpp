// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// `SlidingSyncPos` (ADR-0862): a sliding sync pos is a stream token with an optional page after `.`. MSC4186 makes pos
// opaque to the client, so the page's spelling is this server's choice; these are project-level checks.

#include "merovingian/sync/SlidingSyncPos.hpp"
#include "merovingian/sync/StreamToken.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <cstdint>
#include <limits>
#include <string>

namespace
{

using merovingian::sync::decode_sliding_sync_pos;
using merovingian::sync::encode_sliding_sync_pos;
using merovingian::sync::encode_stream_token;
using merovingian::sync::SlidingSyncPos;
using merovingian::sync::StreamToken;

constexpr auto token = StreamToken{42U, 42U, 7U, 9U};

} // namespace

SCENARIO("a sliding sync pos without a page is its stream token", "[sync][sliding-sync][pos]")
{
    GIVEN("a pos with page 0")
    {
        auto const pos = SlidingSyncPos{token, 0U};
        WHEN("it is written and read back")
        {
            auto const text = encode_sliding_sync_pos(pos);
            auto const read = decode_sliding_sync_pos(text);
            THEN("the text is the token's and reads back as page 0")
            {
                REQUIRE(text == encode_stream_token(token));
                REQUIRE(read.has_value());
                auto const decoded = read.value_or(SlidingSyncPos{});
                REQUIRE(encode_stream_token(decoded.token) == encode_stream_token(token));
                REQUIRE(decoded.page == 0U);
            }
        }
    }
}

SCENARIO("a sliding sync pos with a page round-trips", "[sync][sliding-sync][pos]")
{
    GIVEN("a pos with a page, the largest included")
    {
        auto const page = GENERATE(std::uint64_t{1U}, std::uint64_t{12U}, std::numeric_limits<std::uint64_t>::max());
        auto const pos = SlidingSyncPos{token, page};
        WHEN("it is written and read back")
        {
            auto const text = encode_sliding_sync_pos(pos);
            auto const read = decode_sliding_sync_pos(text);
            THEN("the text is the token, a dot and the decimal page, and the page reads back")
            {
                REQUIRE(text == encode_stream_token(token) + "." + std::to_string(page));
                REQUIRE(read.has_value());
                auto const decoded = read.value_or(SlidingSyncPos{});
                REQUIRE(encode_stream_token(decoded.token) == encode_stream_token(token));
                REQUIRE(decoded.page == page);
            }
        }
    }
}

SCENARIO("a sliding sync pos is refused unless it has its one spelling", "[sync][sliding-sync][pos][boundary]")
{
    GIVEN("a page that is empty, zero, has a leading zero, is not decimal, overflows or is repeated")
    {
        auto const suffix = GENERATE(std::string{"."}, std::string{".0"}, std::string{".01"}, std::string{".1a"},
                                     std::string{".-1"}, std::string{".18446744073709551616"},
                                     std::string{".123456789012345678901"}, std::string{".1.2"});
        WHEN("it is read after a valid token")
        {
            auto const read = decode_sliding_sync_pos(encode_stream_token(token) + suffix);
            THEN("it is refused")
            {
                REQUIRE_FALSE(read.has_value());
            }
        }
    }

    GIVEN("a page after something that is not a stream token")
    {
        WHEN("it is read")
        {
            auto const read = decode_sliding_sync_pos("not-a-token.3");
            THEN("it is refused")
            {
                REQUIRE_FALSE(read.has_value());
            }
        }
    }
}
