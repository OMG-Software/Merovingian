// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// LiveKit's HS256 tokens (ADR-0828): the two typed signers and the verifier. The signed vectors were computed apart from
// this code with Python's `hmac` and `hashlib`; the verifier's vector is RFC 7515 Appendix A.1.

#include "merovingian/crypto/LiveKitToken.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace
{

using merovingian::crypto::LiveKitParticipantGrant;

// The MSC4195 vectors: the identity of `["@alice:example.com","memberABC"]` and the room of
// `["!roomid:example.com","slot1234"]`.
constexpr auto alice_identity = "M3VnsLXrkbxIDINXO64u8PZzFyD9ZYFiQULR2dshWYs";
constexpr auto slot_room = "O8437W3+jmzMVjoIP3tNwbm+XxHQk2iKpOA7aqw3qSc";
constexpr auto api_key = "APIkey_1.x-";

[[nodiscard]] auto counting_secret() -> std::vector<std::uint8_t>
{
    auto secret = std::vector<std::uint8_t>(32U);
    for (auto index = std::size_t{0U}; index < secret.size(); ++index)
    {
        secret[index] = static_cast<std::uint8_t>(index);
    }
    return secret;
}

[[nodiscard]] auto alice_grant(bool can_publish) -> LiveKitParticipantGrant
{
    return LiveKitParticipantGrant{.identity = alice_identity,
                                   .room = slot_room,
                                   .can_publish = can_publish,
                                   .not_before = 1'700'000'000,
                                   .expires = 1'700'003'600};
}

// RFC 7515 A.1's key and token.
constexpr auto rfc7515_key = std::array<std::uint8_t, 64U>{
    0x03U, 0x23U, 0x35U, 0x4bU, 0x2bU, 0x0fU, 0xa5U, 0xbcU, 0x83U, 0x7eU, 0x06U, 0x65U, 0x77U, 0x7bU, 0xa6U, 0x8fU,
    0x5aU, 0xb3U, 0x28U, 0xe6U, 0xf0U, 0x54U, 0xc9U, 0x28U, 0xa9U, 0x0fU, 0x84U, 0xb2U, 0xd2U, 0x50U, 0x2eU, 0xbfU,
    0xd3U, 0xfbU, 0x5aU, 0x92U, 0xd2U, 0x06U, 0x47U, 0xefU, 0x96U, 0x8aU, 0xb4U, 0xc3U, 0x77U, 0x62U, 0x3dU, 0x22U,
    0x3dU, 0x2eU, 0x21U, 0x72U, 0x05U, 0x2eU, 0x4fU, 0x08U, 0xc0U, 0xcdU, 0x9aU, 0xf5U, 0x67U, 0xd0U, 0x80U, 0xa3U};
constexpr auto rfc7515_token =
    "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9p"
    "c19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

[[nodiscard]] auto payload_segment(std::string const& token) -> std::string
{
    auto const first = token.find('.');
    auto const second = token.find('.', first + 1U);
    return token.substr(first + 1U, second - first - 1U);
}

} // namespace

SCENARIO("A participant token is the pinned HS256 JWT for its grant", "[crypto][livekit][rtc]")
{
    GIVEN("a 32-byte secret, an API key and Alice's MSC4195 identity and room")
    {
        auto const secret = counting_secret();

        WHEN("a publishing token and a subscribe-only token are signed")
        {
            auto const publisher =
                merovingian::crypto::sign_livekit_participant_token(api_key, secret, alice_grant(true));
            auto const subscriber =
                merovingian::crypto::sign_livekit_participant_token(api_key, secret, alice_grant(false));

            THEN("each is byte for byte the token computed independently")
            {
                REQUIRE(publisher.has_value());
                REQUIRE(subscriber.has_value());
                CHECK(*publisher ==
                      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                      "eyJleHAiOjE3MDAwMDM2MDAsImlzcyI6IkFQSWtleV8xLngtIiwibmJmIjoxNzAwMDAwMDAwLCJzdWIiOiJNM1Zuc0xYcmti"
                      "eElESU5YTzY0dThQWnpGeUQ5WllGaVFVTFIyZHNoV1lzIiwidmlkZW8iOnsiY2FuUHVibGlzaCI6dHJ1ZSwiY2FuUHVibGlz"
                      "aERhdGEiOnRydWUsImNhblN1YnNjcmliZSI6dHJ1ZSwicm9vbSI6Ik84NDM3VzMram16TVZqb0lQM3ROd2JtK1h4SFFrMmlL"
                      "cE9BN2FxdzNxU2MiLCJyb29tSm9pbiI6dHJ1ZX19.SG0vHhzqCslGsLDX5LZYqggMxPneFx5FQvIqAYQUiH0");
                CHECK(*subscriber ==
                      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                      "eyJleHAiOjE3MDAwMDM2MDAsImlzcyI6IkFQSWtleV8xLngtIiwibmJmIjoxNzAwMDAwMDAwLCJzdWIiOiJNM1Zuc0xYcmti"
                      "eElESU5YTzY0dThQWnpGeUQ5WllGaVFVTFIyZHNoV1lzIiwidmlkZW8iOnsiY2FuUHVibGlzaCI6ZmFsc2UsImNhblB1Ymxp"
                      "c2hEYXRhIjpmYWxzZSwiY2FuU3Vic2NyaWJlIjp0cnVlLCJyb29tIjoiTzg0MzdXMytqbXpNVmpvSVAzdE53Ym0rWHhIUWsy"
                      "aUtwT0E3YXF3M3FTYyIsInJvb21Kb2luIjp0cnVlfX0.AfihjyEiSMPDtr4DhJZ0U4ouv2fsWs2BoKe0fvJGdNE");
            }

            THEN("the payload segments are readable with the standard base64 alphabet")
            {
                REQUIRE(publisher.has_value());
                REQUIRE(subscriber.has_value());
                CHECK(payload_segment(*publisher).find_first_of("-_") == std::string::npos);
                CHECK(payload_segment(*subscriber).find_first_of("-_") == std::string::npos);
            }
        }
    }
}

SCENARIO("A signed participant token verifies and says nothing beyond its grant", "[crypto][livekit][rtc]")
{
    GIVEN("a participant token signed for Alice")
    {
        auto const secret = counting_secret();
        auto const token = merovingian::crypto::sign_livekit_participant_token(api_key, secret, alice_grant(true));
        REQUIRE(token.has_value());

        WHEN("it is verified with the same secret")
        {
            auto const verified = merovingian::crypto::verify_hs256_token(*token, secret);

            THEN("the header and the claims are the ones signed, with no create, admin or hidden right")
            {
                REQUIRE(verified.has_value());
                CHECK(verified->header_json == R"({"alg":"HS256","typ":"JWT"})");
                CHECK(verified->payload_json ==
                      R"({"exp":1700003600,"iss":"APIkey_1.x-","nbf":1700000000,"sub":")" + std::string{alice_identity} +
                          R"(","video":{"canPublish":true,"canPublishData":true,"canSubscribe":true,"room":")" +
                          std::string{slot_room} + R"(","roomJoin":true}})");
                CHECK(verified->payload_json.find("roomCreate") == std::string::npos);
                CHECK(verified->payload_json.find("roomAdmin") == std::string::npos);
                CHECK(verified->payload_json.find("hidden") == std::string::npos);
            }
        }
    }
}

SCENARIO("A room-creation token grants roomCreate and nothing else", "[crypto][livekit][rtc]")
{
    GIVEN("a 32-byte secret and an API key")
    {
        auto const secret = counting_secret();

        WHEN("a room-creation token is signed for one minute")
        {
            auto const token =
                merovingian::crypto::sign_livekit_room_create_token(api_key, secret, 1'700'000'000, 1'700'000'060);

            THEN("it is byte for byte the token computed independently")
            {
                REQUIRE(token.has_value());
                CHECK(*token == "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                                "eyJleHAiOjE3MDAwMDAwNjAsImlzcyI6IkFQSWtleV8xLngtIiwibmJmIjoxNzAwMDAwMDAwLCJ2aWRlbyI6eyJy"
                                "b29tQ3JlYXRlIjp0cnVlfX0.H8s0R8qoKX-6VA99JYKgYg0WktDfwQ-zfAuzjRi8j6M");
            }
        }
    }
}

SCENARIO("The signers refuse a claim or secret they cannot sign safely", "[crypto][livekit][rtc][negative]")
{
    GIVEN("a valid grant, key and secret")
    {
        auto const secret = counting_secret();

        WHEN("one of them is changed to something out of bounds")
        {
            auto const short_secret = std::vector<std::uint8_t>(31U, 0x01U);
            auto with_identity = [](std::string identity) {
                auto grant = alice_grant(true);
                grant.identity = std::move(identity);
                return grant;
            };
            auto with_room = [](std::string room) {
                auto grant = alice_grant(true);
                grant.room = std::move(room);
                return grant;
            };
            auto with_times = [](std::int64_t not_before, std::int64_t expires) {
                auto grant = alice_grant(true);
                grant.not_before = not_before;
                grant.expires = expires;
                return grant;
            };
            auto const sign = [&secret](std::string const& key, LiveKitParticipantGrant const& grant) {
                return merovingian::crypto::sign_livekit_participant_token(key, secret, grant);
            };

            THEN("no token is signed")
            {
                CHECK_FALSE(
                    merovingian::crypto::sign_livekit_participant_token(api_key, short_secret, alice_grant(true)));
                CHECK_FALSE(sign("", alice_grant(true)));
                CHECK_FALSE(sign("key with space", alice_grant(true)));
                CHECK_FALSE(sign(R"(key")", alice_grant(true)));
                CHECK_FALSE(sign(std::string(129U, 'k'), alice_grant(true)));
                CHECK(sign(std::string(128U, 'k'), alice_grant(true)));
                CHECK_FALSE(sign(api_key, with_identity("@alice:example.com")));
                CHECK_FALSE(sign(api_key, with_identity(std::string(42U, 'A'))));
                CHECK_FALSE(sign(api_key, with_identity(std::string(42U, 'A') + "=")));
                CHECK_FALSE(sign(api_key, with_identity(std::string(42U, 'A') + "-")));
                CHECK_FALSE(sign(api_key, with_room(std::string(44U, 'A'))));
                CHECK_FALSE(sign(api_key, with_room(std::string(42U, 'A') + "\"")));
                CHECK_FALSE(sign(api_key, with_times(1'700'000'000, 1'700'000'000)));
                CHECK_FALSE(sign(api_key, with_times(1'700'000'001, 1'700'000'000)));
                CHECK_FALSE(sign(api_key, with_times(-1, 1'700'000'000)));
                CHECK_FALSE(merovingian::crypto::sign_livekit_room_create_token(api_key, short_secret, 0, 60));
                CHECK_FALSE(merovingian::crypto::sign_livekit_room_create_token("bad key", secret, 0, 60));
                CHECK_FALSE(merovingian::crypto::sign_livekit_room_create_token(api_key, secret, 60, 60));
            }
        }
    }
}

SCENARIO("The verifier accepts RFC 7515's HS256 example", "[crypto][livekit][rtc]")
{
    GIVEN("the key and token of RFC 7515 Appendix A.1")
    {
        WHEN("the token is verified")
        {
            auto const verified = merovingian::crypto::verify_hs256_token(rfc7515_token, rfc7515_key);

            THEN("it verifies and its header and payload are the RFC's, line breaks included")
            {
                REQUIRE(verified.has_value());
                CHECK(verified->header_json == "{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}");
                CHECK(verified->payload_json ==
                      "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}");
            }
        }
    }
}

SCENARIO("The verifier refuses a token that is altered, malformed or under another key",
         "[crypto][livekit][rtc][negative]")
{
    GIVEN("a participant token signed with one secret")
    {
        auto const secret = counting_secret();
        auto const token = merovingian::crypto::sign_livekit_participant_token(api_key, secret, alice_grant(false));
        REQUIRE(token.has_value());
        auto const first_dot = token->find('.');
        auto const second_dot = token->find('.', first_dot + 1U);

        WHEN("it is altered or checked under the wrong key")
        {
            auto other_secret = secret;
            other_secret[0] ^= 0x01U;
            auto flipped_payload = *token;
            flipped_payload[first_dot + 5U] = flipped_payload[first_dot + 5U] == 'A' ? 'B' : 'A';
            auto flipped_signature = *token;
            flipped_signature.back() = flipped_signature.back() == 'A' ? 'B' : 'A';
            auto const header = token->substr(0U, first_dot);
            auto const payload = token->substr(first_dot + 1U, second_dot - first_dot - 1U);
            auto const signature = token->substr(second_dot + 1U);
            // `{"alg":"none"}`: an unsigned token is refused whatever its header claims.
            auto const alg_none = std::string{"eyJhbGciOiJub25lIn0."} + payload + ".";

            THEN("none of them verifies")
            {
                CHECK_FALSE(merovingian::crypto::verify_hs256_token(*token, other_secret));
                CHECK_FALSE(merovingian::crypto::verify_hs256_token(*token, std::span{secret}.first(31U)));
                CHECK_FALSE(merovingian::crypto::verify_hs256_token(flipped_payload, secret));
                CHECK_FALSE(merovingian::crypto::verify_hs256_token(flipped_signature, secret));
                CHECK_FALSE(merovingian::crypto::verify_hs256_token(alg_none, secret));
                CHECK_FALSE(merovingian::crypto::verify_hs256_token(header + "." + payload, secret));
                CHECK_FALSE(merovingian::crypto::verify_hs256_token(*token + ".", secret));
                CHECK_FALSE(merovingian::crypto::verify_hs256_token(*token + "." + signature, secret));
                CHECK_FALSE(merovingian::crypto::verify_hs256_token(header + ".." + signature, secret));
                CHECK_FALSE(merovingian::crypto::verify_hs256_token(header + "." + payload + "." + signature + "=",
                                                                    secret));
                CHECK_FALSE(merovingian::crypto::verify_hs256_token(header + "." + payload + "." + signature.substr(1U),
                                                                    secret));
                CHECK_FALSE(merovingian::crypto::verify_hs256_token("", secret));
            }
        }

        WHEN("a token is longer than the bound")
        {
            auto const long_token = std::string(4097U, 'A');

            THEN("it is refused before any decoding")
            {
                CHECK_FALSE(merovingian::crypto::verify_hs256_token(long_token, secret));
            }
        }
    }
}
