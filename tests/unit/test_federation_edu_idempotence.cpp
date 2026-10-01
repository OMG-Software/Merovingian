// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation/edu_idempotence.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <string>

using merovingian::federation::direct_to_device_message_id_is_valid;
using merovingian::federation::EduIdempotenceWindow;

SCENARIO("The to-device idempotence window delivers a message_id once per origin",
         "[federation][edu][to-device][idempotence][security]")
{
    // Spec: SS API v1.19, "Send-to-device messaging": message_id is "used for idempotence".
    GIVEN("an empty window")
    {
        auto window = EduIdempotenceWindow{};
        auto const start = EduIdempotenceWindow::Clock::now();

        WHEN("the same origin sends the same message_id twice")
        {
            auto const first = window.first_sighting("b.example", "m1", start);
            auto const second = window.first_sighting("b.example", "m1", start + std::chrono::seconds{1});

            THEN("only the first sighting is fresh")
            {
                REQUIRE(first);
                REQUIRE_FALSE(second);
                REQUIRE(window.size() == 1U);
            }
        }

        WHEN("two origins use the same message_id")
        {
            auto const from_b = window.first_sighting("b.example", "m1", start);
            auto const from_c = window.first_sighting("c.example", "m1", start);

            THEN("neither suppresses the other")
            {
                REQUIRE(from_b);
                REQUIRE(from_c);
            }
        }

        WHEN("the origin/message_id boundary is shifted")
        {
            auto const first = window.first_sighting("ab", "c", start);
            auto const second = window.first_sighting("a", "bc", start);

            THEN("the two pairs are distinct")
            {
                REQUIRE(first);
                REQUIRE(second);
            }
        }
    }
}

SCENARIO("The to-device idempotence window is bounded in size and in time",
         "[federation][edu][to-device][idempotence][security]")
{
    GIVEN("a window of capacity three with a one hour lifetime")
    {
        auto window = EduIdempotenceWindow{3U, std::chrono::hours{1}};
        auto const start = EduIdempotenceWindow::Clock::now();

        WHEN("four distinct messages arrive")
        {
            for (auto index = 0; index < 4; ++index)
            {
                REQUIRE(window.first_sighting("b.example", "m" + std::to_string(index),
                                              start + std::chrono::seconds{index}));
            }

            THEN("the window never exceeds its capacity")
            {
                REQUIRE(window.size() == 3U);
            }

            AND_THEN("the oldest entry was evicted first, so it is fresh again")
            {
                REQUIRE(window.first_sighting("b.example", "m0", start + std::chrono::seconds{10}));
            }
        }

        WHEN("a message is replayed after the lifetime has elapsed")
        {
            REQUIRE(window.first_sighting("b.example", "m1", start));
            auto const replay_inside = window.first_sighting("b.example", "m1", start + std::chrono::minutes{59});
            auto const replay_outside = window.first_sighting("b.example", "m1", start + std::chrono::minutes{61});

            THEN("it is suppressed inside the window and fresh once the entry has expired")
            {
                REQUIRE_FALSE(replay_inside);
                REQUIRE(replay_outside);
            }
        }
    }
}

SCENARIO("A to-device message_id follows the spec's length rule", "[federation][edu][to-device][idempotence]")
{
    // Spec: message_id is an "Arbitrary utf8 string, of maximum length 32 codepoints."
    GIVEN("message IDs of various shapes")
    {
        THEN("a non-empty ID of at most 32 codepoints is valid")
        {
            REQUIRE(direct_to_device_message_id_is_valid("hiezohf6Hoo7kaev"));
            REQUIRE(direct_to_device_message_id_is_valid(std::string(32U, 'a')));
        }
        THEN("32 multi-byte codepoints are valid although they exceed 32 bytes")
        {
            auto id = std::string{};
            for (auto index = 0; index < 32; ++index)
            {
                id += "\xC3\xA9";
            }
            REQUIRE(direct_to_device_message_id_is_valid(id));
        }
        THEN("an empty ID or one over 32 codepoints is invalid")
        {
            REQUIRE_FALSE(direct_to_device_message_id_is_valid(""));
            REQUIRE_FALSE(direct_to_device_message_id_is_valid(std::string(33U, 'a')));
        }
    }
}
