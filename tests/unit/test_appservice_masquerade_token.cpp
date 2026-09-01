// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |         INTERNAL APPSERVICE MASQUERADE TOKEN — ENCODE / DECODE          |
// |                                                                         |
// |  Spec: Matrix v1.19 Application Service API §"Identity assertion"      |
// |  URL:  ../../docs/matrix-v1.19-spec/application-service-api.md          |
// |                                                                         |
// |  This token never appears on the wire — it is an internal substitute   |
// |  for `access_token` used only for the remainder of one dispatch call,  |
// |  once client_server.cpp has already verified the presented as_token.   |
// |  The property under test here is the round trip and, more importantly,|
// |  that a corrupted/foreign string never partially decodes.             |
// +-------------------------------------------------------------------------+

#include "merovingian/appservice/masquerade_token.hpp"

#include <catch2/catch_test_macros.hpp>

using merovingian::appservice::decode_masquerade_token;
using merovingian::appservice::encode_masquerade_token;
using merovingian::appservice::is_masquerade_token;
using merovingian::appservice::MasqueradeIdentity;

SCENARIO("encoding and decoding a masquerade identity round-trips exactly", "[appservice][masquerade]")
{
    GIVEN("an identity with a device id asserted")
    {
        auto const identity = MasqueradeIdentity{"irc-bridge", "@_irc_bridge_alice:example.org", "DEVICE1"};

        WHEN("it is encoded and decoded")
        {
            auto const token = encode_masquerade_token(identity);
            auto const decoded = decode_masquerade_token(token);

            THEN("every field survives the round trip")
            {
                REQUIRE(decoded.has_value());
                CHECK(decoded->appservice_id == identity.appservice_id);
                CHECK(decoded->user_id == identity.user_id);
                CHECK(decoded->device_id == identity.device_id);
            }
        }
    }

    GIVEN("an identity with no device id asserted")
    {
        auto const identity = MasqueradeIdentity{"irc-bridge", "@_irc_bot:example.org", ""};

        WHEN("it is encoded and decoded")
        {
            auto const token = encode_masquerade_token(identity);
            auto const decoded = decode_masquerade_token(token);

            THEN("device_id decodes back to empty")
            {
                REQUIRE(decoded.has_value());
                CHECK(decoded->device_id.empty());
            }
        }
    }

    GIVEN("a user id that itself contains ':' characters, like every real Matrix user id")
    {
        // The whole reason this format uses length prefixes instead of a
        // delimiter: user ids and appservice ids both routinely contain ':'.
        auto const identity = MasqueradeIdentity{"irc:bridge:with:colons", "@alice:sub.example.org:8448", "d:1"};

        WHEN("it is encoded and decoded")
        {
            auto const token = encode_masquerade_token(identity);
            auto const decoded = decode_masquerade_token(token);

            THEN("fields are not corrupted by the embedded colons")
            {
                REQUIRE(decoded.has_value());
                CHECK(decoded->appservice_id == identity.appservice_id);
                CHECK(decoded->user_id == identity.user_id);
                CHECK(decoded->device_id == identity.device_id);
            }
        }
    }
}

SCENARIO("decode_masquerade_token fails closed on anything malformed", "[appservice][masquerade][security]")
{
    GIVEN("an ordinary opaque bearer token with no relation to the reserved format")
    {
        WHEN("is_masquerade_token / decode_masquerade_token are called")
        {
            THEN("it is not recognised as a masquerade token")
            {
                CHECK_FALSE(is_masquerade_token("syt_YWxpY2U_abcdefghijklmnop_12345"));
                CHECK_FALSE(decode_masquerade_token("syt_YWxpY2U_abcdefghijklmnop_12345").has_value());
            }
        }
    }

    GIVEN("the reserved prefix followed by a truncated body")
    {
        WHEN("decode_masquerade_token is called")
        {
            THEN("it fails closed rather than throwing or partially decoding")
            {
                CHECK_FALSE(decode_masquerade_token("appservice-masquerade:v1:5:abc").has_value());
            }
        }
    }

    GIVEN("the reserved prefix with a length prefix that overruns the string")
    {
        WHEN("decode_masquerade_token is called")
        {
            THEN("it fails closed")
            {
                CHECK_FALSE(decode_masquerade_token("appservice-masquerade:v1:999:short").has_value());
            }
        }
    }

    GIVEN("the reserved prefix with a non-numeric length field")
    {
        WHEN("decode_masquerade_token is called")
        {
            THEN("it fails closed")
            {
                CHECK_FALSE(decode_masquerade_token("appservice-masquerade:v1:abc:x0:y0:z").has_value());
            }
        }
    }

    GIVEN("a well-formed token with trailing garbage appended")
    {
        auto const identity = MasqueradeIdentity{"a", "b", "c"};
        auto const token = encode_masquerade_token(identity) + "trailing-junk";

        WHEN("decode_masquerade_token is called")
        {
            THEN("the trailing bytes are not silently ignored")
            {
                CHECK_FALSE(decode_masquerade_token(token).has_value());
            }
        }
    }

    GIVEN("an empty string")
    {
        WHEN("is_masquerade_token is called")
        {
            THEN("it is false")
            {
                CHECK_FALSE(is_masquerade_token(""));
            }
        }
    }
}
