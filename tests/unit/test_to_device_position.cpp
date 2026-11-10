// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/sync/ToDevicePosition.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <cstdint>
#include <limits>
#include <string>

// ADR-0592: the sliding sync to_device extension's position acknowledges every message at or below its stream id,
// so it must decode exactly and carry the stream token epoch it was issued in. The reader it replaces stopped at
// the first non-digit, so "12abc" acknowledged everything up to 12.
SCENARIO("A to-device position round-trips with and without an epoch", "[sync][to-device][restore]")
{
    GIVEN("a position with an epoch and one without")
    {
        auto const with_epoch = merovingian::sync::ToDevicePosition{20U, 18446744073709551615ULL};
        auto const without_epoch = merovingian::sync::ToDevicePosition{20U, 0U};

        WHEN("both are encoded and decoded")
        {
            auto const encoded_with = merovingian::sync::encode_to_device_position(with_epoch);
            auto const encoded_without = merovingian::sync::encode_to_device_position(without_epoch);
            auto const decoded_with = merovingian::sync::decode_to_device_position(encoded_with);
            auto const decoded_without = merovingian::sync::decode_to_device_position(encoded_without);

            THEN("the epoch follows an underscore, and is left out when it is zero")
            {
                REQUIRE(encoded_with == "20_18446744073709551615");
                REQUIRE(encoded_without == "20");
            }

            THEN("each decodes to what was encoded")
            {
                REQUIRE(decoded_with.has_value());
                REQUIRE(decoded_with->stream_id == 20U);
                REQUIRE(decoded_with->epoch == std::numeric_limits<std::uint64_t>::max());
                REQUIRE(decoded_without.has_value());
                REQUIRE(decoded_without->stream_id == 20U);
                REQUIRE(decoded_without->epoch == 0U);
            }
        }
    }
}

SCENARIO("A to-device position that encode_to_device_position does not write is refused",
         "[sync][to-device][restore][security]")
{
    GIVEN("malformed positions")
    {
        auto const malformed = GENERATE(as<std::string>{}, "", "12abc", "-1", "+1", "012", "18446744073709551616",
                                        "99999999999999999999999", "20_", "20_0", "20_07", "20_5_6", "_5", "20_x");

        WHEN("decoded: '" + malformed + "'")
        {
            auto const decoded = merovingian::sync::decode_to_device_position(malformed);

            THEN("it does not decode")
            {
                REQUIRE_FALSE(decoded.has_value());
            }
        }
    }

    GIVEN("the largest and smallest stream ids")
    {
        WHEN("each is decoded")
        {
            auto const largest = merovingian::sync::decode_to_device_position("18446744073709551615");
            auto const smallest = merovingian::sync::decode_to_device_position("0");

            THEN("both decode exactly")
            {
                REQUIRE(largest.has_value());
                REQUIRE(largest->stream_id == std::numeric_limits<std::uint64_t>::max());
                REQUIRE(smallest.has_value());
                REQUIRE(smallest->stream_id == 0U);
            }
        }
    }
}
