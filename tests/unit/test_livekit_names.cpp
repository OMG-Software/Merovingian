// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// The LiveKit room name and participant identity MSC4195 derives (ADR-0829). The first two vectors are the MSC's own;
// the rest were computed apart from this code with Python's `json` and `hashlib`.

#include "merovingian/crypto/LiveKitToken.hpp"
#include "merovingian/homeserver/LiveKitNames.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

SCENARIO("The LiveKit names match MSC4195's vectors", "[homeserver][livekit][rtc]")
{
    GIVEN("the MSC's room and slot, and its user and member")
    {
        WHEN("the room name and identity are derived")
        {
            auto const room = merovingian::homeserver::livekit_room_name("!roomid:example.com", "slot1234");
            auto const identity =
                merovingian::homeserver::livekit_participant_identity("@alice:example.com", "memberABC");

            THEN("they are the MSC's values, and a valid LiveKit name each")
            {
                REQUIRE(room.has_value());
                REQUIRE(identity.has_value());
                CHECK(*room == "O8437W3+jmzMVjoIP3tNwbm+XxHQk2iKpOA7aqw3qSc");
                CHECK(*identity == "M3VnsLXrkbxIDINXO64u8PZzFyD9ZYFiQULR2dshWYs");
                CHECK(merovingian::crypto::livekit_name_is_valid(*room));
                CHECK(merovingian::crypto::livekit_name_is_valid(*identity));
            }
        }
    }
}

SCENARIO("The legacy call slot names the same LiveKit room as the stable one", "[homeserver][livekit][rtc]")
{
    GIVEN("one room and the two spellings of the call slot")
    {
        WHEN("both room names are derived")
        {
            auto const stable = merovingian::homeserver::livekit_room_name("!roomid:example.com", "m.call#room");
            auto const legacy = merovingian::homeserver::livekit_room_name("!roomid:example.com", "m.call#ROOM");
            auto const other = merovingian::homeserver::livekit_room_name("!roomid:example.com", "m.call#Room");

            THEN("both are the hash of the stable slot, and no other spelling is folded")
            {
                REQUIRE(stable.has_value());
                REQUIRE(legacy.has_value());
                REQUIRE(other.has_value());
                CHECK(*stable == "2EPGhjulIGe4Sqyrrzv9fQuklBFly+CBIEYlCRUmJ5E");
                CHECK(*legacy == *stable);
                CHECK(*other != *stable);
            }
        }
    }
}

SCENARIO("The LiveKit names hash canonical JSON, escapes and non-ASCII included", "[homeserver][livekit][rtc]")
{
    GIVEN("member IDs with non-ASCII and with characters JSON escapes")
    {
        WHEN("the identities are derived")
        {
            auto const accented =
                merovingian::homeserver::livekit_participant_identity("@alice:example.com", "caf\xC3\xA9\xE2\x98\x83");
            auto const escaped =
                merovingian::homeserver::livekit_participant_identity("@alice:example.com", "a\"b\\c\nd");

            THEN("each is the independently computed hash")
            {
                REQUIRE(accented.has_value());
                REQUIRE(escaped.has_value());
                CHECK(*accented == "TMP0XlNvSwylAPHKC8kFbPdxQaz1HyqWuO6pX7ilfhI");
                CHECK(*escaped == "FXIBqDUROwH93ach69WuL2jLRKoQq47pNLYhXP16hMs");
            }
        }
    }

    GIVEN("a member ID that is not valid UTF-8")
    {
        WHEN("an identity is derived")
        {
            auto const identity =
                merovingian::homeserver::livekit_participant_identity("@alice:example.com", std::string{"\xC3"});

            THEN("there is none")
            {
                CHECK_FALSE(identity.has_value());
            }
        }
    }
}
