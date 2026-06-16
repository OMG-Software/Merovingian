// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/crypto/constant_time.hpp"
#include "merovingian/crypto/ed25519.hpp"
#include "merovingian/crypto/random.hpp"
#include "merovingian/crypto/signing_service.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <string_view>
#include <utility>

namespace
{

class FixedSigningKeyStore final : public merovingian::crypto::SigningKeyStore
{
public:
    explicit FixedSigningKeyStore(merovingian::crypto::SigningKeyRecord key)
        : m_key{std::move(key)}
    {
    }

    [[nodiscard]] auto active_key_for_server(std::string_view server_name)
        -> merovingian::crypto::SigningKeyLookupResult override
    {
        if (server_name != m_key.server_name)
        {
            return {{}, "signing key not found"};
        }

        return {m_key, {}};
    }

private:
    merovingian::crypto::SigningKeyRecord m_key{};
};

class FixedEd25519Provider final : public merovingian::crypto::Ed25519Provider
{
public:
    [[nodiscard]] auto sign(merovingian::crypto::Ed25519SecretKeyHandle const& key, std::string_view message)
        -> merovingian::crypto::SignatureResult override
    {
        if (key.key_id != "ed25519:auto")
        {
            return {{}, "unknown key"};
        }
        if (message.empty())
        {
            return {{}, "message is empty"};
        }

        return {merovingian::crypto::Ed25519Signature{std::string(64U, 's')}, {}};
    }

    [[nodiscard]] auto verify(merovingian::crypto::Ed25519PublicKey const& public_key, std::string_view message,
                              merovingian::crypto::Ed25519Signature const& signature)
        -> merovingian::crypto::VerificationResult override
    {
        auto const valid =
            public_key.bytes.size() == 32U && !message.empty() && signature.bytes == std::string(64U, 's');
        return {valid, valid ? std::string{} : std::string{"signature verification failed"}};
    }
};

} // namespace

SCENARIO("Crypto constant-time equality preserves exact comparison semantics", "[crypto]")
{
    GIVEN("matching and non-matching byte strings")
    {
        auto constexpr value = "same-secret";
        auto constexpr different_value = "same-secreu";
        auto constexpr shorter_value = "same";

        WHEN("the values are compared")
        {
            auto const matching = merovingian::crypto::constant_time_equal(value, value);
            auto const different = merovingian::crypto::constant_time_equal(value, different_value);
            auto const shorter = merovingian::crypto::constant_time_equal(value, shorter_value);

            THEN("only exact matches are accepted")
            {
                REQUIRE(matching);
                REQUIRE_FALSE(different);
                REQUIRE_FALSE(shorter);
            }
        }
    }
}

SCENARIO("Crypto constant-time equality holds at boundaries", "[crypto][security][boundary]")
{
    GIVEN("empty, equal-length-differing, and length-mismatched byte strings")
    {
        WHEN("the values are compared")
        {
            auto const empty_equal = merovingian::crypto::constant_time_equal("", "");
            auto const differ_last_byte = merovingian::crypto::constant_time_equal("secret-aaaa", "secret-aaab");
            auto const identical = merovingian::crypto::constant_time_equal("secret-aaaa", "secret-aaaa");
            auto const length_mismatch = merovingian::crypto::constant_time_equal("secret", "secrets");

            THEN("only exact, equal-length matches are accepted")
            {
                REQUIRE(empty_equal);
                REQUIRE_FALSE(differ_last_byte);
                REQUIRE(identical);
                REQUIRE_FALSE(length_mismatch);
            }
        }
    }
}

SCENARIO("Crypto random boundary rejects invalid request sizes", "[crypto]")
{
    GIVEN("zero, bounded, and oversized requests")
    {
        WHEN("request sizes are validated")
        {
            auto const zero_allowed = merovingian::crypto::random_size_is_allowed(0U);
            auto const bounded_allowed = merovingian::crypto::random_size_is_allowed(32U);
            auto const oversized_allowed = merovingian::crypto::random_size_is_allowed(4097U);

            THEN("only bounded non-zero requests are allowed")
            {
                REQUIRE_FALSE(zero_allowed);
                REQUIRE(bounded_allowed);
                REQUIRE_FALSE(oversized_allowed);
            }
        }
    }
}

SCENARIO("Crypto Ed25519 boundary validates key and signature shapes", "[crypto]")
{
    GIVEN("valid and invalid Ed25519-shaped values")
    {
        auto const valid_public_key = merovingian::crypto::Ed25519PublicKey{std::string(32U, 'p')};
        auto const invalid_public_key = merovingian::crypto::Ed25519PublicKey{std::string(31U, 'p')};
        auto const valid_signature = merovingian::crypto::Ed25519Signature{std::string(64U, 's')};
        auto const invalid_signature = merovingian::crypto::Ed25519Signature{std::string(63U, 's')};

        WHEN("the shapes are validated")
        {
            auto const valid_public_key_result =
                merovingian::crypto::ed25519_public_key_shape_is_valid(valid_public_key);
            auto const invalid_public_key_result =
                merovingian::crypto::ed25519_public_key_shape_is_valid(invalid_public_key);
            auto const valid_signature_result = merovingian::crypto::ed25519_signature_shape_is_valid(valid_signature);
            auto const invalid_signature_result =
                merovingian::crypto::ed25519_signature_shape_is_valid(invalid_signature);
            auto const valid_key_id_result = merovingian::crypto::ed25519_key_id_is_valid("ed25519:auto");
            auto const invalid_key_id_result = merovingian::crypto::ed25519_key_id_is_valid("rsa:auto");

            THEN("only Ed25519-shaped values are accepted")
            {
                REQUIRE(valid_public_key_result);
                REQUIRE_FALSE(invalid_public_key_result);
                REQUIRE(valid_signature_result);
                REQUIRE_FALSE(invalid_signature_result);
                REQUIRE(valid_key_id_result);
                REQUIRE_FALSE(invalid_key_id_result);
            }
        }
    }
}

SCENARIO("Crypto signing service signs with the active server key", "[crypto][signing]")
{
    GIVEN("an active signing key and provider")
    {
        auto store = FixedSigningKeyStore{
            merovingian::crypto::SigningKeyRecord{
                                                  "example.org", "ed25519:auto",
                                                  merovingian::crypto::Ed25519PublicKey{std::string(32U, 'p')},
                                                  true, }
        };
        auto provider = FixedEd25519Provider{};

        WHEN("a server signature is requested")
        {
            auto const result = merovingian::crypto::sign_for_server(store, provider, "example.org", "payload");

            THEN("the active key is used")
            {
                REQUIRE(result.error.empty());
                REQUIRE(result.server_name == "example.org");
                REQUIRE(result.key_id == "ed25519:auto");
                REQUIRE(result.signature.bytes == std::string(64U, 's'));
            }
        }
    }
}

SCENARIO("Crypto signing service fails closed for unusable keys", "[crypto][signing]")
{
    GIVEN("an inactive signing key")
    {
        auto store = FixedSigningKeyStore{
            merovingian::crypto::SigningKeyRecord{
                                                  "example.org", "ed25519:auto",
                                                  merovingian::crypto::Ed25519PublicKey{std::string(32U, 'p')},
                                                  false, }
        };
        auto provider = FixedEd25519Provider{};

        WHEN("a server signature is requested")
        {
            auto const result = merovingian::crypto::sign_for_server(store, provider, "example.org", "payload");

            THEN("signing is rejected")
            {
                REQUIRE_FALSE(result.error.empty());
                REQUIRE(result.error == "active signing key is not usable");
            }
        }
    }
}
