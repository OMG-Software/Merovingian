// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation/edu_idempotence.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <string>

using merovingian::federation::derive_direct_to_device_message_id;
using merovingian::federation::direct_to_device_message_id_is_valid;
using merovingian::federation::EduIdempotenceWindow;

SCENARIO("The to-device idempotence window reports a message once it has been recorded",
         "[federation][edu][to-device][idempotence][security]")
{
    // Spec: SS API v1.19, "Send-to-device messaging": message_id is "used for idempotence".
    GIVEN("an empty window")
    {
        auto window = EduIdempotenceWindow{};
        auto const start = EduIdempotenceWindow::Clock::now();

        WHEN("a message is only looked up")
        {
            auto const first = window.seen("b.example", "@u:b.example", "m1", start);
            auto const second = window.seen("b.example", "@u:b.example", "m1", start);

            THEN("looking it up never records it")
            {
                REQUIRE_FALSE(first);
                REQUIRE_FALSE(second);
                REQUIRE(window.size() == 0U);
            }
        }

        WHEN("the same (origin, sender, message_id) is recorded")
        {
            window.record("b.example", "@u:b.example", "m1", start);

            THEN("it is seen afterwards, and recording it again does not grow the window")
            {
                REQUIRE(window.seen("b.example", "@u:b.example", "m1", start + std::chrono::seconds{1}));
                window.record("b.example", "@u:b.example", "m1", start + std::chrono::seconds{2});
                REQUIRE(window.size() == 1U);
            }
        }

        WHEN("two origins use the same sender and message_id")
        {
            window.record("b.example", "@u:b.example", "m1", start);

            THEN("one does not suppress the other")
            {
                REQUIRE_FALSE(window.seen("c.example", "@u:b.example", "m1", start));
            }
        }

        WHEN("one origin uses the same message_id for two different senders")
        {
            window.record("b.example", "@u:b.example", "m1", start);

            THEN("the second sender's message is not a replay of the first")
            {
                REQUIRE_FALSE(window.seen("b.example", "@v:b.example", "m1", start));
                REQUIRE(window.seen("b.example", "@u:b.example", "m1", start));
            }
        }

        WHEN("the boundaries between origin, sender and message_id are shifted")
        {
            window.record("ab", "c", "d", start);

            THEN("no shifted triple matches the recorded one")
            {
                REQUIRE_FALSE(window.seen("a", "bc", "d", start));
                REQUIRE_FALSE(window.seen("ab", "cd", "", start));
                REQUIRE_FALSE(window.seen("abc", "", "d", start));
                REQUIRE(window.seen("ab", "c", "d", start));
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

        WHEN("four distinct messages are recorded")
        {
            for (auto index = 0; index < 4; ++index)
            {
                window.record("b.example", "@u:b.example", "m" + std::to_string(index),
                              start + std::chrono::seconds{index});
            }

            THEN("the window never exceeds its capacity")
            {
                REQUIRE(window.size() == 3U);
            }

            AND_THEN("the oldest entry was evicted first, so it is no longer seen")
            {
                REQUIRE_FALSE(window.seen("b.example", "@u:b.example", "m0", start + std::chrono::seconds{10}));
                REQUIRE(window.seen("b.example", "@u:b.example", "m3", start + std::chrono::seconds{10}));
            }
        }

        WHEN("a message is replayed after the lifetime has elapsed")
        {
            window.record("b.example", "@u:b.example", "m1", start);

            THEN("it is seen inside the window and forgotten once the entry has expired")
            {
                REQUIRE(window.seen("b.example", "@u:b.example", "m1", start + std::chrono::minutes{59}));
                REQUIRE_FALSE(window.seen("b.example", "@u:b.example", "m1", start + std::chrono::minutes{61}));
            }
        }

        WHEN("a new message is recorded after older ones have expired")
        {
            window.record("b.example", "@u:b.example", "old", start);
            window.record("b.example", "@u:b.example", "new", start + std::chrono::minutes{90});

            THEN("the expired entry has been dropped")
            {
                REQUIRE(window.size() == 1U);
            }
        }
    }

    GIVEN("a window with no capacity")
    {
        auto window = EduIdempotenceWindow{0U, std::chrono::hours{1}};
        auto const start = EduIdempotenceWindow::Clock::now();

        WHEN("a message is recorded")
        {
            window.record("b.example", "@u:b.example", "m1", start);

            THEN("nothing is retained")
            {
                REQUIRE(window.size() == 0U);
                REQUIRE_FALSE(window.seen("b.example", "@u:b.example", "m1", start));
            }
        }
    }
}

SCENARIO("A derived to-device message_id is stable per request, distinct per sender and spec-valid",
         "[federation][edu][to-device][message-id]")
{
    // Spec: message_id is an "Arbitrary utf8 string, of maximum length 32 codepoints." Client
    // transaction IDs are only unique per user, so the ID is derived from the sender as well.
    GIVEN("two senders who use the same client transaction ID")
    {
        auto const alice = derive_direct_to_device_message_id("@alice:a.example", "m.room.encrypted", "1");
        auto const bob = derive_direct_to_device_message_id("@bob:a.example", "m.room.encrypted", "1");

        THEN("their message IDs differ")
        {
            REQUIRE(alice.has_value());
            REQUIRE(bob.has_value());
            REQUIRE(*alice != *bob);
        }
    }

    GIVEN("one sender repeating the same request")
    {
        auto const first = derive_direct_to_device_message_id("@alice:a.example", "m.room.encrypted", "txn-7");
        auto const second = derive_direct_to_device_message_id("@alice:a.example", "m.room.encrypted", "txn-7");

        THEN("the message ID is the same, so a resend is recognised as a replay")
        {
            REQUIRE(first.has_value());
            REQUIRE(first == second);
        }
    }

    GIVEN("requests that differ in event type or transaction ID only")
    {
        auto const base = derive_direct_to_device_message_id("@alice:a.example", "m.room.encrypted", "txn-7");
        auto const other_type = derive_direct_to_device_message_id("@alice:a.example", "m.room_key_request", "txn-7");
        auto const other_txn = derive_direct_to_device_message_id("@alice:a.example", "m.room.encrypted", "txn-8");

        THEN("each gets its own message ID")
        {
            REQUIRE(base.has_value());
            REQUIRE(other_type.has_value());
            REQUIRE(other_txn.has_value());
            REQUIRE(*base != *other_type);
            REQUIRE(*base != *other_txn);
        }
    }

    GIVEN("inputs whose boundaries are shifted")
    {
        auto const first = derive_direct_to_device_message_id("ab", "c", "d");
        auto const second = derive_direct_to_device_message_id("a", "bc", "d");
        auto const third = derive_direct_to_device_message_id("ab", "cd", "");

        THEN("they cannot collide")
        {
            REQUIRE(first.has_value());
            REQUIRE(second.has_value());
            REQUIRE(third.has_value());
            REQUIRE(*first != *second);
            REQUIRE(*first != *third);
            REQUIRE(*second != *third);
        }
    }

    GIVEN("transaction IDs of awkward shapes")
    {
        auto const long_txn = derive_direct_to_device_message_id("@alice:a.example", "m.test", std::string(200U, 'x'));
        auto const multibyte_txn =
            derive_direct_to_device_message_id("@alice:a.example", "m.test", "\xC3\xA9\xE2\x82\xAC");
        auto const nul_txn = derive_direct_to_device_message_id("@alice:a.example", "m.test", std::string{"a\0b", 3U});
        auto const plain_txn = derive_direct_to_device_message_id("@alice:a.example", "m.test", "a");

        THEN("every derived ID is non-empty, at most 32 codepoints and passes the validity check")
        {
            REQUIRE(long_txn.has_value());
            REQUIRE(multibyte_txn.has_value());
            REQUIRE(nul_txn.has_value());
            REQUIRE(plain_txn.has_value());
            REQUIRE(direct_to_device_message_id_is_valid(*long_txn));
            REQUIRE(direct_to_device_message_id_is_valid(*multibyte_txn));
            REQUIRE(direct_to_device_message_id_is_valid(*nul_txn));
            REQUIRE(*nul_txn != *plain_txn);
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
