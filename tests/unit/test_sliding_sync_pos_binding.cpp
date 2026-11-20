// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// MSC4186 "Connections": "Servers MUST reject a `pos` that was not issued to the requesting user and device". The
// server sends a `pos` bound to both with a keyed hash (ADR-0866); these scenarios prove only the issuing user and
// device get the position back, and that nothing else does.

#include "merovingian/homeserver/SlidingSyncPosBinding.hpp"
#include "merovingian/sync/SlidingSyncPos.hpp"
#include "merovingian/sync/StreamToken.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace
{

using merovingian::homeserver::bind_sliding_sync_pos;
using merovingian::homeserver::unbind_sliding_sync_pos;

constexpr auto alice = std::string_view{"@alice:example.org"};
constexpr auto bob = std::string_view{"@bob:example.org"};
constexpr auto device = std::string_view{"ALICEDEVICE"};
constexpr auto pos = std::string_view{"s42_42_7_9.3"};

[[nodiscard]] auto key_of(std::uint8_t fill) -> std::array<std::uint8_t, 32U>
{
    auto key = std::array<std::uint8_t, 32U>{};
    key.fill(fill);
    return key;
}

} // namespace

SCENARIO("a bound sliding sync pos is given back only to the user and device it was issued to",
         "[sync][sliding-sync][pos][security]")
{
    GIVEN("a pos bound to alice's device with the server's key")
    {
        auto const key = key_of(0x5AU);
        auto const bound = bind_sliding_sync_pos(pos, alice, device, key);
        REQUIRE(bound.has_value());
        auto const text = bound.value_or(std::string{});

        THEN("it is the pos, a dash and 64 lowercase hex digits")
        {
            REQUIRE(text.size() == pos.size() + 1U + 64U);
            REQUIRE(text.starts_with(pos));
            REQUIRE(text[pos.size()] == '-');
            REQUIRE(text.find_first_not_of("0123456789abcdef", pos.size() + 1U) == std::string::npos);
        }

        WHEN("alice's device sends it back")
        {
            auto const unbound = unbind_sliding_sync_pos(text, alice, device, key);
            THEN("the pos it carries is returned")
            {
                REQUIRE(unbound.has_value());
                REQUIRE(unbound.value_or(std::string_view{}) == pos);
            }
        }

        WHEN("bob, alice's other device, or a server with another key sends it")
        {
            auto const other_key = key_of(0xA5U);
            THEN("it is refused")
            {
                REQUIRE_FALSE(unbind_sliding_sync_pos(text, bob, device, key).has_value());
                REQUIRE_FALSE(unbind_sliding_sync_pos(text, alice, "OTHERDEVICE", key).has_value());
                REQUIRE_FALSE(unbind_sliding_sync_pos(text, alice, device, other_key).has_value());
            }
        }

        WHEN("it is altered, cut short or sent without its hash")
        {
            auto altered_pos = text;
            altered_pos[1] = altered_pos[1] == '4' ? '5' : '4';
            auto altered_mac = text;
            altered_mac.back() = altered_mac.back() == '0' ? '1' : '0';
            auto upper_mac = text;
            for (auto i = pos.size() + 1U; i < upper_mac.size(); ++i)
            {
                if (upper_mac[i] >= 'a' && upper_mac[i] <= 'f')
                {
                    upper_mac[i] = static_cast<char>(upper_mac[i] - 'a' + 'A');
                }
            }
            auto const variant = GENERATE_COPY(altered_pos, altered_mac, text.substr(0U, text.size() - 1U),
                                               std::string{pos}, std::string{pos} + "-", text + "0", std::string{});
            THEN("it is refused")
            {
                REQUIRE_FALSE(unbind_sliding_sync_pos(variant, alice, device, key).has_value());
            }
            if (upper_mac != text)
            {
                THEN("the hash in upper case is refused as well: it has one spelling")
                {
                    REQUIRE_FALSE(unbind_sliding_sync_pos(upper_mac, alice, device, key).has_value());
                }
            }
        }
    }
}

SCENARIO("a sliding sync pos is never bound without a key, and no two users' bindings coincide",
         "[sync][sliding-sync][pos][security]")
{
    GIVEN("no key")
    {
        WHEN("a pos is bound or unbound")
        {
            auto const bound = bind_sliding_sync_pos(pos, alice, device, {});
            THEN("neither is done: the server never issues an unbound pos")
            {
                REQUIRE_FALSE(bound.has_value());
                REQUIRE_FALSE(unbind_sliding_sync_pos(std::string{pos} + "-" + std::string(64U, '0'), alice, device, {})
                                  .has_value());
            }
        }
    }

    GIVEN("two users whose IDs and device IDs join to the same text")
    {
        auto const key = key_of(0x11U);
        WHEN("a pos is bound to each")
        {
            auto const first = bind_sliding_sync_pos(pos, "@a:x.org", "BC", key);
            auto const second = bind_sliding_sync_pos(pos, "@a:x.orgB", "C", key);
            THEN("the bindings differ, so neither can use the other's")
            {
                REQUIRE(first.has_value());
                REQUIRE(second.has_value());
                REQUIRE(first != second);
                REQUIRE_FALSE(
                    unbind_sliding_sync_pos(first.value_or(std::string{}), "@a:x.orgB", "C", key).has_value());
            }
        }
    }
}

// MSC4186 "Connections": "A `pos` token can be used in `/messages` and `/relations` APIs, in the same way as a
// `next_batch` from `/v3/sync`"; MSC4543 adds `/keys/changes`.
SCENARIO("a sync position token is a stream token or a bound sliding sync pos", "[sync][sliding-sync][pos]")
{
    constexpr auto token = merovingian::sync::StreamToken{42U, 42U, 7U, 9U};
    auto const stream_text = merovingian::sync::encode_stream_token(token);

    GIVEN("a /sync next_batch and a bound pos with a page")
    {
        auto const key = key_of(0x22U);
        auto const bound =
            bind_sliding_sync_pos(stream_text + ".3", alice, device, key).value_or(std::string{"missing"});
        WHEN("each is read as a pagination token")
        {
            auto const plain = merovingian::sync::decode_sync_position_token(stream_text);
            auto const from_pos = merovingian::sync::decode_sync_position_token(bound);
            THEN("both name the same stream position")
            {
                REQUIRE(plain.has_value());
                REQUIRE(from_pos.has_value());
                REQUIRE(merovingian::sync::encode_stream_token(from_pos.value_or(merovingian::sync::StreamToken{})) ==
                        stream_text);
            }
        }
    }

    GIVEN("text that is neither")
    {
        auto const text =
            GENERATE_COPY(std::string{}, std::string{"not-a-token"}, stream_text + "-",
                          stream_text + "-" + std::string(63U, 'a'), stream_text + "-" + std::string(64U, 'G'),
                          stream_text + "-" + std::string(64U, 'A'), std::string{"-"} + std::string(64U, 'a'));
        WHEN("it is read as a pagination token")
        {
            auto const read = merovingian::sync::decode_sync_position_token(text);
            THEN("it is refused")
            {
                REQUIRE_FALSE(read.has_value());
            }
        }
    }
}
