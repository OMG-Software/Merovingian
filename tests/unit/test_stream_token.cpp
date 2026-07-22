// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/sync/stream_token.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <limits>
#include <string>

SCENARIO("Stream tokens encode and decode round-trip", "[sync][stream-token]")
{
    GIVEN("a stream token with event and membership orderings")
    {
        auto const token = merovingian::sync::StreamToken{42U, 7U};

        WHEN("the token is encoded and decoded")
        {
            auto const encoded = merovingian::sync::encode_stream_token(token);
            auto const decoded = merovingian::sync::decode_stream_token(encoded);

            THEN("the decoded token matches the original")
            {
                REQUIRE(decoded.has_value());
                REQUIRE(decoded->event_ordering == 42U);
                REQUIRE(decoded->membership_ordering == 7U);
            }
        }
    }
}

SCENARIO("Stream tokens with zero orderings are valid", "[sync][stream-token]")
{
    GIVEN("a stream token with zero orderings")
    {
        auto const token = merovingian::sync::StreamToken{0U, 0U};

        WHEN("the token is encoded and decoded")
        {
            auto const encoded = merovingian::sync::encode_stream_token(token);
            auto const decoded = merovingian::sync::decode_stream_token(encoded);

            THEN("the decoded token preserves zero values")
            {
                REQUIRE(decoded.has_value());
                REQUIRE(decoded->event_ordering == 0U);
                REQUIRE(decoded->membership_ordering == 0U);
            }
        }
    }
}

SCENARIO("Stream tokens with large orderings encode correctly", "[sync][stream-token]")
{
    GIVEN("a stream token with a large event ordering")
    {
        auto const token = merovingian::sync::StreamToken{1000000U, 500U};

        WHEN("the token is encoded")
        {
            auto const encoded = merovingian::sync::encode_stream_token(token);

            THEN("the encoded form contains the expected hex components")
            {
                REQUIRE(encoded.find('_') != std::string::npos);
                auto const decoded = merovingian::sync::decode_stream_token(encoded);
                REQUIRE(decoded.has_value());
                REQUIRE(decoded->event_ordering == 1000000U);
                REQUIRE(decoded->membership_ordering == 500U);
            }
        }
    }
}

SCENARIO("Invalid stream tokens are rejected", "[sync][stream-token]")
{
    GIVEN("an empty string")
    {
        WHEN("decoded")
        {
            auto const decoded = merovingian::sync::decode_stream_token("");

            THEN("the result is nullopt")
            {
                REQUIRE_FALSE(decoded.has_value());
            }
        }
    }

    GIVEN("a string with no separator")
    {
        WHEN("decoded")
        {
            auto const decoded = merovingian::sync::decode_stream_token("abc");

            THEN("the result is nullopt")
            {
                REQUIRE_FALSE(decoded.has_value());
            }
        }
    }

    GIVEN("a string with invalid hex characters")
    {
        WHEN("decoded")
        {
            auto const decoded = merovingian::sync::decode_stream_token("zz_invalid");

            THEN("the result is nullopt")
            {
                REQUIRE_FALSE(decoded.has_value());
            }
        }
    }
}

SCENARIO("is_valid_stream_token validates stream tokens", "[sync][stream-token]")
{
    GIVEN("a valid encoded stream token")
    {
        auto const token = merovingian::sync::StreamToken{100U, 50U};
        auto const encoded = merovingian::sync::encode_stream_token(token);

        WHEN("validated")
        {
            THEN("the token is valid")
            {
                REQUIRE(merovingian::sync::is_valid_stream_token(encoded));
            }
        }
    }

    GIVEN("an invalid stream token string")
    {
        WHEN("validated")
        {
            THEN("garbage is rejected")
            {
                REQUIRE_FALSE(merovingian::sync::is_valid_stream_token("garbage"));
            }

            THEN("empty is rejected")
            {
                REQUIRE_FALSE(merovingian::sync::is_valid_stream_token(""));
            }

            THEN("missing separator is rejected")
            {
                REQUIRE_FALSE(merovingian::sync::is_valid_stream_token("abc"));
            }
        }
    }
}

SCENARIO("Initial sync token encodes position zero", "[sync][stream-token]")
{
    GIVEN("the initial stream position representing the start of the event stream")
    {
        auto const initial = merovingian::sync::StreamToken{0U, 0U};

        WHEN("encoded")
        {
            auto const encoded = merovingian::sync::encode_stream_token(initial);

            THEN("the token is non-empty and decodable")
            {
                REQUIRE_FALSE(encoded.empty());
                REQUIRE(merovingian::sync::is_valid_stream_token(encoded));
            }
        }
    }
}

SCENARIO("Stream tokens advance monotonically", "[sync][stream-token]")
{
    GIVEN("two stream tokens where the second is later")
    {
        auto const earlier = merovingian::sync::StreamToken{10U, 5U};
        auto const later = merovingian::sync::StreamToken{20U, 15U};

        WHEN("both are encoded")
        {
            auto const earlier_encoded = merovingian::sync::encode_stream_token(earlier);
            auto const later_encoded = merovingian::sync::encode_stream_token(later);

            THEN("each decodes to its original position")
            {
                auto const earlier_decoded = merovingian::sync::decode_stream_token(earlier_encoded);
                auto const later_decoded = merovingian::sync::decode_stream_token(later_encoded);
                REQUIRE(earlier_decoded.has_value());
                REQUIRE(later_decoded.has_value());
                REQUIRE(earlier_decoded->event_ordering < later_decoded->event_ordering);
                REQUIRE(earlier_decoded->membership_ordering < later_decoded->membership_ordering);
            }
        }
    }
}
// Regression for #456: decode_component had no length cap, so a 17+ digit hex
// component silently wrapped around uint64_t — a crafted pos token like
// "ffffffffffffffff00_0_0" decoded to a truncated (small) ordering, defeating
// the pos never-regress guarantee for malformed input.
SCENARIO("Over-long stream token components are rejected instead of wrapping", "[sync][stream-token][security]")
{
    GIVEN("tokens whose hex components exceed 64 bits")
    {
        auto const wrapping = std::string{"ffffffffffffffff00_0_0"};
        auto const wrapping_membership = std::string{"0_10000000000000000_0"};
        auto const max_valid = std::string{"ffffffffffffffff_ffffffffffffffff_ffffffffffffffff"};

        WHEN("the tokens are decoded")
        {
            auto const wrapped = merovingian::sync::decode_stream_token(wrapping);
            auto const wrapped_membership = merovingian::sync::decode_stream_token(wrapping_membership);
            auto const decoded_max = merovingian::sync::decode_stream_token(max_valid);

            THEN("components longer than 16 hex digits are rejected")
            {
                REQUIRE_FALSE(wrapped.has_value());
                REQUIRE_FALSE(wrapped_membership.has_value());
            }

            THEN("a full-width 16-digit component still decodes")
            {
                REQUIRE(decoded_max.has_value());
                REQUIRE(decoded_max->event_ordering == std::numeric_limits<std::uint64_t>::max());
            }
        }
    }
}
