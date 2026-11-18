// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// The OAuth 2.0 client ID (plan P2, ADR-0779): a keyed BLAKE2b-256 hash of the accepted client metadata, under a key
// derived from the master key with a label of its own, written in unpadded URL-safe base64.

#include "merovingian/crypto/OAuthClientId.hpp"
#include "merovingian/crypto/TokenKey.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

namespace
{

[[nodiscard]] auto client_id_key(std::uint8_t fill) -> merovingian::crypto::TokenHmacKey
{
    auto const material = std::vector<std::uint8_t>(32U, fill);
    auto key = merovingian::crypto::derive_oauth_client_id_key(material);
    REQUIRE(key.has_value());
    return *key;
}

[[nodiscard]] auto is_url_safe(std::string const& text) -> bool
{
    return std::ranges::all_of(text, [](char const value) {
        return (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z') || (value >= '0' && value <= '9') ||
               value == '-' || value == '_';
    });
}

} // namespace

SCENARIO("The OAuth client ID key is separate from every access-token key", "[crypto][token_key][oauth][boundary]")
{
    GIVEN("one master key byte string")
    {
        auto const material = std::vector<std::uint8_t>(32U, 0x5AU);

        WHEN("the client ID key and both access-token keys are derived from it")
        {
            auto const client_id = merovingian::crypto::derive_oauth_client_id_key(material);
            auto const v4 = merovingian::crypto::derive_token_hmac_key(material);
            auto const v3 = merovingian::crypto::derive_token_hmac_key_v3(material);

            THEN("all three derivations succeed and the client ID key equals neither token key")
            {
                REQUIRE(client_id.has_value());
                REQUIRE(v4.has_value());
                REQUIRE(v3.has_value());
                CHECK(client_id->bytes != v4->bytes);
                CHECK(client_id->bytes != v3->bytes);
            }
        }

        WHEN("the client ID key is derived from empty material")
        {
            auto const refused = merovingian::crypto::derive_oauth_client_id_key(std::vector<std::uint8_t>{});

            THEN("it is refused")
            {
                CHECK_FALSE(refused.has_value());
            }
        }
    }
}

SCENARIO("A client ID is a deterministic keyed hash in URL-safe characters", "[crypto][oauth][client_id]")
{
    GIVEN("a client ID key and two canonical metadata texts")
    {
        auto const key = client_id_key(0x11U);
        auto const metadata = std::string{R"({"application_type":"web","client_uri":"https://a.example"})"};
        auto const other = std::string{R"({"application_type":"web","client_uri":"https://b.example"})"};

        WHEN("the ID of each is computed, the first twice")
        {
            auto const first = merovingian::crypto::oauth_client_id(metadata, key);
            auto const again = merovingian::crypto::oauth_client_id(metadata, key);
            auto const different = merovingian::crypto::oauth_client_id(other, key);

            THEN("the same metadata gives the same ID and other metadata another one")
            {
                REQUIRE(first.has_value());
                REQUIRE(again.has_value());
                REQUIRE(different.has_value());
                CHECK(*first == *again);
                CHECK(*first != *different);
            }

            THEN("the ID is 43 characters of A-Z a-z 0-9 - and _")
            {
                REQUIRE(first.has_value());
                CHECK(first->size() == merovingian::crypto::oauth_client_id_chars);
                CHECK(is_url_safe(*first));
            }
        }

        WHEN("the same metadata is hashed under the key of another master key")
        {
            auto const here = merovingian::crypto::oauth_client_id(metadata, key);
            auto const elsewhere = merovingian::crypto::oauth_client_id(metadata, client_id_key(0x22U));

            THEN("the IDs differ, so an ID cannot be computed without this server's key")
            {
                REQUIRE(here.has_value());
                REQUIRE(elsewhere.has_value());
                CHECK(*here != *elsewhere);
            }
        }
    }
}
