// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/crypto/constant_time.hpp"
#include "merovingian/crypto/ed25519.hpp"
#include "merovingian/crypto/random.hpp"
#include "merovingian/crypto/secret_box.hpp"
#include "merovingian/crypto/signing_service.hpp"
#include "merovingian/crypto/token_key.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <string_view>
#include <utility>

#include <sodium.h>

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

SCENARIO("Crypto variable-length constant-time comparison hides length differences", "[crypto][security][boundary]")
{
    GIVEN("equal and unequal strings with different lengths")
    {
        WHEN("the values are compared without a length check")
        {
            auto const identical = merovingian::crypto::constant_time_equal_variable_length("secret", "secret");
            auto const different_same_length =
                merovingian::crypto::constant_time_equal_variable_length("secret", "secreu");
            auto const different_length =
                merovingian::crypto::constant_time_equal_variable_length("secret", "secret-longer");
            auto const empty_vs_value = merovingian::crypto::constant_time_equal_variable_length("", "secret");
            auto const empty_vs_empty = merovingian::crypto::constant_time_equal_variable_length("", "");

            THEN("only exact content matches are accepted regardless of length")
            {
                REQUIRE(identical);
                REQUIRE_FALSE(different_same_length);
                REQUIRE_FALSE(different_length);
                REQUIRE_FALSE(empty_vs_value);
                REQUIRE(empty_vs_empty);
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

SCENARIO("SecretBox derives the same key from identical master material", "[crypto][secret_box]")
{
    GIVEN("two equal master key byte strings")
    {
        auto const material = std::vector<std::uint8_t>{0x01U, 0x02U, 0x03U, 0x04U, 0x05U};

        WHEN("keys are derived")
        {
            auto const key_a = merovingian::crypto::derive_secret_box_key(material);
            auto const key_b = merovingian::crypto::derive_secret_box_key(material);

            THEN("both derivations succeed and produce identical keys")
            {
                REQUIRE(key_a.has_value());
                REQUIRE(key_b.has_value());
                REQUIRE(key_a->bytes == key_b->bytes);
            }
        }
    }
}

SCENARIO("SecretBox round-trips plaintext through authenticated encryption", "[crypto][secret_box]")
{
    GIVEN("a derived key and a secret message")
    {
        auto const master = std::vector<std::uint8_t>{0x0aU, 0x0bU, 0x0cU, 0x0dU};
        auto const key = merovingian::crypto::derive_secret_box_key(master);
        REQUIRE(key.has_value());

        auto const plaintext = std::vector<std::uint8_t>{0xdeU, 0xadU, 0xbeU, 0xefU};

        WHEN("the plaintext is encrypted and then decrypted")
        {
            auto const ciphertext = merovingian::crypto::secret_box_encrypt(plaintext, *key);
            REQUIRE(ciphertext.has_value());
            REQUIRE(ciphertext->bytes.size() > plaintext.size());

            auto const decrypted = merovingian::crypto::secret_box_decrypt(*ciphertext, *key);

            THEN("the decrypted bytes match the original plaintext")
            {
                REQUIRE(decrypted.has_value());
                REQUIRE(*decrypted == plaintext);
            }
        }
    }
}

SCENARIO("SecretBox fails closed when ciphertext is tampered", "[crypto][secret_box]")
{
    GIVEN("a valid ciphertext and a different key")
    {
        auto const master = std::vector<std::uint8_t>{0x10U, 0x20U, 0x30U, 0x40U};
        auto const key = merovingian::crypto::derive_secret_box_key(master);
        REQUIRE(key.has_value());

        auto const plaintext = std::vector<std::uint8_t>{0xcaU, 0xfeU, 0xbaU, 0xbeU};
        auto ciphertext = merovingian::crypto::secret_box_encrypt(plaintext, *key);
        REQUIRE(ciphertext.has_value());

        WHEN("the ciphertext is corrupted")
        {
            ciphertext->bytes.back() ^= 0xFFU;
            auto const decrypted = merovingian::crypto::secret_box_decrypt(*ciphertext, *key);

            THEN("decryption is rejected")
            {
                REQUIRE_FALSE(decrypted.has_value());
            }
        }

        WHEN("a different derived key is used")
        {
            auto const other_master = std::vector<std::uint8_t>{0x50U, 0x60U, 0x70U, 0x80U};
            auto const other_key = merovingian::crypto::derive_secret_box_key(other_master);
            REQUIRE(other_key.has_value());

            auto const decrypted = merovingian::crypto::secret_box_decrypt(*ciphertext, *other_key);

            THEN("decryption is rejected")
            {
                REQUIRE_FALSE(decrypted.has_value());
            }
        }
    }
}

SCENARIO("SecretBox encryption uses a fresh nonce per call", "[crypto][secret_box]")
{
    GIVEN("a derived key and a fixed plaintext")
    {
        auto const master = std::vector<std::uint8_t>{0xaaU, 0xbbU, 0xccU, 0xddU};
        auto const key = merovingian::crypto::derive_secret_box_key(master);
        REQUIRE(key.has_value());

        auto const plaintext = std::vector<std::uint8_t>(32U, 0x55U);

        WHEN("the same plaintext is encrypted twice")
        {
            auto const a = merovingian::crypto::secret_box_encrypt(plaintext, *key);
            auto const b = merovingian::crypto::secret_box_encrypt(plaintext, *key);

            THEN("the ciphertexts differ but both decrypt to the original plaintext")
            {
                REQUIRE(a.has_value());
                REQUIRE(b.has_value());
                REQUIRE(a->bytes != b->bytes);
                REQUIRE(*merovingian::crypto::secret_box_decrypt(*a, *key) == plaintext);
                REQUIRE(*merovingian::crypto::secret_box_decrypt(*b, *key) == plaintext);
            }
        }
    }
}

SCENARIO("SecretBox fails closed with empty or short input", "[crypto][secret_box]")
{
    GIVEN("a derived SecretBox key")
    {
        auto const master = std::vector<std::uint8_t>(crypto_generichash_KEYBYTES, 0xABU);
        auto const key = merovingian::crypto::derive_secret_box_key(master);
        REQUIRE(key.has_value());

        THEN("deriving a key from empty material fails closed")
        {
            auto const empty = std::vector<std::uint8_t>{};
            REQUIRE_FALSE(merovingian::crypto::derive_secret_box_key(empty).has_value());
        }

        THEN("encrypting empty plaintext fails closed")
        {
            auto const empty = std::vector<std::uint8_t>{};
            REQUIRE_FALSE(merovingian::crypto::secret_box_encrypt(empty, *key).has_value());
        }

        THEN("decrypting a ciphertext shorter than nonce+mac fails closed")
        {
            auto const short_ciphertext = merovingian::crypto::SecretBoxCiphertext{
                .bytes = std::vector<std::uint8_t>(crypto_secretbox_NONCEBYTES, 0U)};
            REQUIRE_FALSE(merovingian::crypto::secret_box_decrypt(short_ciphertext, *key).has_value());
        }
    }
}

SCENARIO("TokenHmacKey derives the same key from identical master material", "[crypto][token_key]")
{
    GIVEN("two equal master key byte strings")
    {
        auto const material = std::vector<std::uint8_t>{0x01U, 0x02U, 0x03U, 0x04U, 0x05U};

        WHEN("token HMAC keys are derived")
        {
            auto const key_a = merovingian::crypto::derive_token_hmac_key(material);
            auto const key_b = merovingian::crypto::derive_token_hmac_key(material);

            THEN("both derivations succeed and produce identical keys")
            {
                REQUIRE(key_a.has_value());
                REQUIRE(key_b.has_value());
                REQUIRE(key_a->bytes == key_b->bytes);
            }
        }
    }
}

SCENARIO("TokenHmacKey domain separation produces a different key than SecretBox", "[crypto][token_key][boundary]")
{
    GIVEN("a single master key byte string")
    {
        auto const material = std::vector<std::uint8_t>(32U, 0xABU);

        WHEN("the same material is used for both token HMAC and SecretBox keys")
        {
            auto const token_key = merovingian::crypto::derive_token_hmac_key(material);
            auto const secret_key = merovingian::crypto::derive_secret_box_key(material);

            THEN("the derived keys are distinct and both derivations succeed")
            {
                REQUIRE(token_key.has_value());
                REQUIRE(secret_key.has_value());
                REQUIRE(token_key->bytes != secret_key->bytes);
            }
        }
    }
}

SCENARIO("TokenHmacKey fails closed with empty material", "[crypto][token_key]")
{
    GIVEN("empty master key material")
    {
        auto const empty = std::vector<std::uint8_t>{};

        WHEN("a token HMAC key is derived")
        {
            auto const key = merovingian::crypto::derive_token_hmac_key(empty);

            THEN("derivation is rejected")
            {
                REQUIRE_FALSE(key.has_value());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// signing_key_record_is_usable — direct validation
// ---------------------------------------------------------------------------

namespace
{

[[nodiscard]] auto make_key(std::string server_name, std::string key_id, std::size_t pk_bytes,
                            bool active) -> merovingian::crypto::SigningKeyRecord
{
    return {std::move(server_name), std::move(key_id),
            merovingian::crypto::Ed25519PublicKey{std::string(pk_bytes, 'p')}, active};
}

class MismatchedSigningKeyStore final : public merovingian::crypto::SigningKeyStore
{
public:
    [[nodiscard]] auto active_key_for_server(std::string_view) -> merovingian::crypto::SigningKeyLookupResult override
    {
        // Always returns a key whose server_name differs from any queried server.
        return {make_key("imposter.org", "ed25519:auto", 32U, true), {}};
    }
};

class BadShapeEd25519Provider final : public merovingian::crypto::Ed25519Provider
{
public:
    [[nodiscard]] auto sign(merovingian::crypto::Ed25519SecretKeyHandle const&, std::string_view)
        -> merovingian::crypto::SignatureResult override
    {
        // Returns a 63-byte signature — one byte short of the required 64.
        return {merovingian::crypto::Ed25519Signature{std::string(63U, 'x')}, {}};
    }

    [[nodiscard]] auto verify(merovingian::crypto::Ed25519PublicKey const&, std::string_view,
                              merovingian::crypto::Ed25519Signature const&)
        -> merovingian::crypto::VerificationResult override
    {
        return {false, "not implemented"};
    }
};

} // namespace

SCENARIO("signing_key_record_is_usable validates all required key record fields", "[crypto][signing]")
{
    GIVEN("key records with varying field validity")
    {
        WHEN("all fields are correct and the key is active")
        {
            THEN("the key is usable")
            {
                REQUIRE(merovingian::crypto::signing_key_record_is_usable(make_key("example.org", "ed25519:auto", 32U, true)));
            }
        }

        WHEN("the key is inactive (active = false)")
        {
            THEN("the key is not usable — inactive keys must not be used for signing")
            {
                REQUIRE_FALSE(
                    merovingian::crypto::signing_key_record_is_usable(make_key("example.org", "ed25519:auto", 32U, false)));
            }
        }

        WHEN("server_name is empty")
        {
            THEN("the key is not usable — server identity is required")
            {
                REQUIRE_FALSE(merovingian::crypto::signing_key_record_is_usable(make_key("", "ed25519:auto", 32U, true)));
            }
        }

        WHEN("key_id has a non-Ed25519 prefix")
        {
            THEN("the key is not usable — key_id must pass ed25519_key_id_is_valid")
            {
                REQUIRE_FALSE(merovingian::crypto::signing_key_record_is_usable(make_key("example.org", "rsa:key", 32U, true)));
            }
        }

        WHEN("the public key is 31 bytes (wrong size)")
        {
            THEN("the key is not usable — invalid public key shape")
            {
                REQUIRE_FALSE(merovingian::crypto::signing_key_record_is_usable(make_key("example.org", "ed25519:auto", 31U, true)));
            }
        }
    }
}

SCENARIO("Crypto signing service rejects an empty server name", "[crypto][signing][error]")
{
    GIVEN("a valid key store and provider")
    {
        auto store = FixedSigningKeyStore{
            merovingian::crypto::SigningKeyRecord{
                "example.org", "ed25519:auto",
                merovingian::crypto::Ed25519PublicKey{std::string(32U, 'p')},
                true,
            }
        };
        auto provider = FixedEd25519Provider{};

        WHEN("sign_for_server is called with an empty server name")
        {
            auto const result = merovingian::crypto::sign_for_server(store, provider, "", "payload");

            THEN("signing is rejected with 'server name is empty'")
            {
                REQUIRE_FALSE(result.error.empty());
                REQUIRE(result.error == "server name is empty");
            }
        }
    }
}

SCENARIO("Crypto signing service propagates key store errors", "[crypto][signing][error]")
{
    GIVEN("a key store that holds a key only for example.org")
    {
        auto store = FixedSigningKeyStore{
            merovingian::crypto::SigningKeyRecord{
                "example.org", "ed25519:auto",
                merovingian::crypto::Ed25519PublicKey{std::string(32U, 'p')},
                true,
            }
        };
        auto provider = FixedEd25519Provider{};

        WHEN("signing is requested for a server not in the store")
        {
            auto const result = merovingian::crypto::sign_for_server(store, provider, "other.org", "payload");

            THEN("signing fails with the key store's error message")
            {
                REQUIRE_FALSE(result.error.empty());
                REQUIRE(result.error == "signing key not found");
            }
        }
    }
}

SCENARIO("Crypto signing service rejects a key whose server_name mismatches the request",
         "[crypto][signing][error][security]")
{
    GIVEN("a key store that always returns a key for 'imposter.org'")
    {
        auto store = MismatchedSigningKeyStore{};
        auto provider = FixedEd25519Provider{};

        WHEN("signing is requested for example.org")
        {
            auto const result = merovingian::crypto::sign_for_server(store, provider, "example.org", "payload");

            THEN("signing is rejected — server_name in the returned key does not match the request")
            {
                REQUIRE_FALSE(result.error.empty());
                REQUIRE(result.error == "active signing key server mismatch");
            }
        }
    }
}

SCENARIO("Crypto signing service propagates provider errors", "[crypto][signing][error]")
{
    GIVEN("a valid key store and a provider that rejects empty messages")
    {
        auto store = FixedSigningKeyStore{
            merovingian::crypto::SigningKeyRecord{
                "example.org", "ed25519:auto",
                merovingian::crypto::Ed25519PublicKey{std::string(32U, 'p')},
                true,
            }
        };
        auto provider = FixedEd25519Provider{};

        WHEN("sign_for_server is called with an empty message")
        {
            auto const result = merovingian::crypto::sign_for_server(store, provider, "example.org", "");

            THEN("signing fails with the provider's error — the message was rejected")
            {
                REQUIRE_FALSE(result.error.empty());
                REQUIRE(result.server_name == "example.org");
                REQUIRE(result.key_id == "ed25519:auto");
            }
        }
    }
}

SCENARIO("Crypto signing service rejects a provider signature with invalid byte count",
         "[crypto][signing][error][security]")
{
    GIVEN("a valid key store and a provider that returns a 63-byte signature")
    {
        auto store = FixedSigningKeyStore{
            merovingian::crypto::SigningKeyRecord{
                "example.org", "ed25519:auto",
                merovingian::crypto::Ed25519PublicKey{std::string(32U, 'p')},
                true,
            }
        };
        auto provider = BadShapeEd25519Provider{};

        WHEN("signing is attempted")
        {
            auto const result = merovingian::crypto::sign_for_server(store, provider, "example.org", "payload");

            THEN("signing fails — a malformed signature shape is never forwarded")
            {
                REQUIRE_FALSE(result.error.empty());
                REQUIRE(result.error == "provider returned invalid Ed25519 signature shape");
                REQUIRE(result.server_name == "example.org");
                REQUIRE(result.key_id == "ed25519:auto");
            }
        }
    }
}
