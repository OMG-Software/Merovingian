// SPDX-License-Identifier: GPL-3.0-or-later

#include "../support/temp_directory.hpp"
#include "merovingian/core/secret_buffer.hpp"
#include "merovingian/crypto/constant_time.hpp"
#include "merovingian/crypto/ed25519.hpp"
#include "merovingian/crypto/encoding.hpp"
#include "merovingian/crypto/generic_hash.hpp"
#include "merovingian/crypto/ipc_auth_key.hpp"
#include "merovingian/crypto/master_key.hpp"
#include "merovingian/crypto/random.hpp"
#include "merovingian/crypto/runtime_ed25519_provider.hpp"
#include "merovingian/crypto/runtime_multikey_ed25519_provider.hpp"
#include "merovingian/crypto/secret_box.hpp"
#include "merovingian/crypto/signing_service.hpp"
#include "merovingian/crypto/token_key.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <ranges>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <span>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

#include <sodium.h>
#include <unistd.h>

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

SCENARIO("Crypto variable-length constant-time comparison fails closed on hash errors", "[crypto][security][boundary]")
{
    // libsodium hash failures cannot be triggered reliably from a unit test,
    // but the observable contract is that any failure inside the hash path
    // must return false rather than fall open.  We verify the normal unequal
    // cases still reject, which is the only externally testable surface of
    // the fail-closed path.
    GIVEN("strings that differ in content or length")
    {
        WHEN("the comparison is made")
        {
            auto const different_content =
                merovingian::crypto::constant_time_equal_variable_length("merovingian:a", "merovingian:b");
            auto const different_length =
                merovingian::crypto::constant_time_equal_variable_length("short", "a-much-longer-secret");

            THEN("the result is false")
            {
                REQUIRE_FALSE(different_content);
                REQUIRE_FALSE(different_length);
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
                REQUIRE(result.error == "no active signing key");
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
                REQUIRE(std::ranges::equal(decrypted->bytes(), plaintext));
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
                REQUIRE(std::ranges::equal(merovingian::crypto::secret_box_decrypt(*a, *key)->bytes(), plaintext));
                REQUIRE(std::ranges::equal(merovingian::crypto::secret_box_decrypt(*b, *key)->bytes(), plaintext));
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
// derive_token_hmac_key_v3 — issue #322 key separation
// ---------------------------------------------------------------------------
// The legacy v3 access-token HMAC key MUST be derived from the operator's
// master key (NOT the Ed25519 signing seed), using a domain separator distinct
// from the v4 key. This guarantees (a) v3 and v4 keys are independent and
// (b) the v3 key has no relationship to the Ed25519 seed that previously backed
// it. Existing seed-derived v3 hashes are invalidated by this change; affected
// sessions must re-login and are upgraded to v4.
SCENARIO("derive_token_hmac_key_v3 is domain-separated from v4 and from the Ed25519 seed",
         "[crypto][token_key][security]")
{
    GIVEN("master key material, an Ed25519-shaped seed, and a token")
    {
        auto const material = std::vector<std::uint8_t>(32U, 0xABU);
        auto const seed = std::vector<std::uint8_t>(crypto_sign_SECRETKEYBYTES, 0x11U);
        auto const token = std::vector<std::uint8_t>{'m', 'v', 's', '_', 't', 'o', 'k', 'e', 'n'};

        WHEN("v3 and v4 keys are derived and the token is hashed under each key and under the raw seed")
        {
            auto const v3_key = merovingian::crypto::derive_token_hmac_key_v3(material);
            auto const v4_key = merovingian::crypto::derive_token_hmac_key(material);
            REQUIRE(v3_key.has_value());
            REQUIRE(v4_key.has_value());

            // Old (pre-#322) v3 HMAC key: the first 32 bytes of the Ed25519 seed.
            auto old_seed_key = std::array<unsigned char, crypto_generichash_KEYBYTES>{};
            std::copy_n(seed.begin(), crypto_generichash_KEYBYTES, old_seed_key.begin());

            auto hash_under = [](std::vector<std::uint8_t> const& tok, std::span<unsigned char const> key) {
                auto digest = std::array<unsigned char, 32U>{};
                std::ignore =
                    crypto_generichash(digest.data(), digest.size(), tok.data(), tok.size(), key.data(), key.size());
                return digest;
            };
            auto const v3_hash = hash_under(token, v3_key->bytes);
            auto const v4_hash = hash_under(token, v4_key->bytes);
            auto const old_seed_hash = hash_under(token, old_seed_key);

            THEN("the v3 key differs from the v4 key and from the raw seed key")
            {
                // Spec MUST (#322): full key separation from the Ed25519 seed.
                REQUIRE(v3_key->bytes != old_seed_key);
                // Domain separation: v3 and v4 derive independent keys from the same master material.
                REQUIRE(v3_key->bytes != v4_key->bytes);
                // Consequently the token hashes under each key are all distinct.
                REQUIRE(v3_hash != v4_hash);
                REQUIRE(v3_hash != old_seed_hash);
            }
        }
    }
}

SCENARIO("derive_token_hmac_key_v3 is deterministic and fails closed on empty material",
         "[crypto][token_key][security]")
{
    GIVEN("two equal master key byte strings and one empty string")
    {
        auto const material = std::vector<std::uint8_t>{0x01U, 0x02U, 0x03U, 0x04U, 0x05U};
        auto const empty = std::vector<std::uint8_t>{};

        WHEN("v3 keys are derived")
        {
            auto const key_a = merovingian::crypto::derive_token_hmac_key_v3(material);
            auto const key_b = merovingian::crypto::derive_token_hmac_key_v3(material);
            auto const key_empty = merovingian::crypto::derive_token_hmac_key_v3(empty);

            THEN("identical material yields identical keys and empty material is rejected")
            {
                REQUIRE(key_a.has_value());
                REQUIRE(key_b.has_value());
                REQUIRE(key_a->bytes == key_b->bytes);
                REQUIRE_FALSE(key_empty.has_value());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// signing_key_record_is_usable — direct validation
// ---------------------------------------------------------------------------

namespace
{

[[nodiscard]] auto make_key(std::string server_name, std::string key_id, std::size_t pk_bytes, bool active)
    -> merovingian::crypto::SigningKeyRecord
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
                REQUIRE(merovingian::crypto::signing_key_record_is_usable(
                    make_key("example.org", "ed25519:auto", 32U, true)));
            }
        }

        WHEN("the key is inactive (active = false)")
        {
            THEN("the key is not usable — inactive keys must not be used for signing")
            {
                REQUIRE_FALSE(merovingian::crypto::signing_key_record_is_usable(
                    make_key("example.org", "ed25519:auto", 32U, false)));
            }
        }

        WHEN("server_name is empty")
        {
            THEN("the key is not usable — server identity is required")
            {
                REQUIRE_FALSE(
                    merovingian::crypto::signing_key_record_is_usable(make_key("", "ed25519:auto", 32U, true)));
            }
        }

        WHEN("key_id has a non-Ed25519 prefix")
        {
            THEN("the key is not usable — key_id must pass ed25519_key_id_is_valid")
            {
                REQUIRE_FALSE(
                    merovingian::crypto::signing_key_record_is_usable(make_key("example.org", "rsa:key", 32U, true)));
            }
        }

        WHEN("the public key is 31 bytes (wrong size)")
        {
            THEN("the key is not usable — invalid public key shape")
            {
                REQUIRE_FALSE(merovingian::crypto::signing_key_record_is_usable(
                    make_key("example.org", "ed25519:auto", 31U, true)));
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
                                                  true, }
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

SCENARIO("Crypto signing service reports no active signing key when the store has no matching key",
         "[crypto][signing][error]")
{
    GIVEN("a key store that holds a key only for example.org")
    {
        auto store = FixedSigningKeyStore{
            merovingian::crypto::SigningKeyRecord{
                                                  "example.org", "ed25519:auto",
                                                  merovingian::crypto::Ed25519PublicKey{std::string(32U, 'p')},
                                                  true, }
        };
        auto provider = FixedEd25519Provider{};

        WHEN("signing is requested for a server not in the store")
        {
            auto const result = merovingian::crypto::sign_for_server(store, provider, "other.org", "payload");

            THEN("signing fails because no usable active key is available for that server")
            {
                REQUIRE_FALSE(result.error.empty());
                REQUIRE(result.error == "no active signing key");
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

            THEN("signing is rejected because no returned key matches the requested server")
            {
                REQUIRE_FALSE(result.error.empty());
                REQUIRE(result.error == "no usable active signing key");
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
                                                  true, }
        };
        auto provider = FixedEd25519Provider{};

        WHEN("sign_for_server is called with an empty message")
        {
            auto const result = merovingian::crypto::sign_for_server(store, provider, "example.org", "");

            THEN("signing fails with the provider's error and no signature is produced")
            {
                REQUIRE_FALSE(result.error.empty());
                REQUIRE(result.error == "message is empty");
                REQUIRE(result.server_name.empty());
                REQUIRE(result.key_id.empty());
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
                                                  true, }
        };
        auto provider = BadShapeEd25519Provider{};

        WHEN("signing is attempted")
        {
            auto const result = merovingian::crypto::sign_for_server(store, provider, "example.org", "payload");

            THEN("signing fails — a malformed signature shape is never forwarded")
            {
                REQUIRE_FALSE(result.error.empty());
                REQUIRE(result.error == "provider returned invalid Ed25519 signature shape");
                REQUIRE(result.server_name.empty());
                REQUIRE(result.key_id.empty());
            }
        }
    }
}

namespace
{

[[nodiscard]] auto write_master_key_file(std::string_view content) -> std::filesystem::path
{
    auto const path = merovingian::tests::temporary_directory() /
                      ("merovingian-master-key-test-" +
                       std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + ".bin");
    auto stream = std::ofstream{path, std::ios::binary};
    stream.write(content.data(), static_cast<std::streamsize>(content.size()));
    stream.close();
    return path;
}

} // namespace

SCENARIO("load_master_key_material returns a SecretBuffer with the file's exact bytes", "[crypto][master_key]")
{
    GIVEN("a master key file containing arbitrary binary content, including embedded NUL bytes")
    {
        auto const content = std::string{"\x00\x01\xffsome-master-key-bytes", 24U};
        auto const path = write_master_key_file(content);

        WHEN("the material is loaded")
        {
            auto const material = merovingian::crypto::load_master_key_material(path.string());

            THEN("it succeeds and the bytes match exactly, unaffected by the embedded NUL")
            {
                REQUIRE(material.has_value());
                REQUIRE(material->bytes().size() == content.size());
                // Compare as unsigned bytes: content.begin() iterates plain
                // (possibly signed) char, so 0xFF read from an ASCII escape
                // would compare unequal to the same bit pattern in a
                // std::uint8_t span via operator== integer promotion.
                REQUIRE(std::equal(material->bytes().begin(), material->bytes().end(), content.begin(), content.end(),
                                   [](std::uint8_t lhs, char rhs) noexcept {
                                       return lhs == static_cast<std::uint8_t>(rhs);
                                   }));
            }
        }

        std::filesystem::remove(path);
    }
}

SCENARIO("load_master_key_material fails closed for missing, empty, and oversized files", "[crypto][master_key]")
{
    GIVEN("an empty path")
    {
        WHEN("the material is loaded")
        {
            THEN("it fails closed")
            {
                REQUIRE_FALSE(merovingian::crypto::load_master_key_material("").has_value());
            }
        }
    }

    GIVEN("a path that does not exist")
    {
        WHEN("the material is loaded")
        {
            THEN("it fails closed")
            {
                REQUIRE_FALSE(
                    merovingian::crypto::load_master_key_material("/nonexistent/merovingian-master-key").has_value());
            }
        }
    }

    GIVEN("an empty master key file")
    {
        auto const path = write_master_key_file("");

        WHEN("the material is loaded")
        {
            THEN("it fails closed")
            {
                REQUIRE_FALSE(merovingian::crypto::load_master_key_material(path.string()).has_value());
            }
        }

        std::filesystem::remove(path);
    }

    GIVEN("a master key file exceeding the 4096-byte cap")
    {
        auto const path = write_master_key_file(std::string(4097U, 'x'));

        WHEN("the material is loaded")
        {
            THEN("it fails closed rather than silently truncating")
            {
                REQUIRE_FALSE(merovingian::crypto::load_master_key_material(path.string()).has_value());
            }
        }

        std::filesystem::remove(path);
    }

    GIVEN("a master key file exactly at the 4096-byte cap")
    {
        auto const path = write_master_key_file(std::string(4096U, 'y'));

        WHEN("the material is loaded")
        {
            THEN("it succeeds")
            {
                auto const material = merovingian::crypto::load_master_key_material(path.string());
                REQUIRE(material.has_value());
                REQUIRE(material->bytes().size() == 4096U);
            }
        }

        std::filesystem::remove(path);
    }
}

SCENARIO("load_master_key_material's output derives working keys through every downstream KDF", "[crypto][master_key]")
{
    GIVEN("a real master key file")
    {
        auto const path = write_master_key_file("integration-master-key-material");

        WHEN("the material is loaded and used to derive each dependent key")
        {
            auto const material = merovingian::crypto::load_master_key_material(path.string());
            REQUIRE(material.has_value());

            auto const secret_box_key = merovingian::crypto::derive_secret_box_key(material->bytes());
            auto const token_key_v4 = merovingian::crypto::derive_token_hmac_key(material->bytes());
            auto const token_key_v3 = merovingian::crypto::derive_token_hmac_key_v3(material->bytes());
            auto const ipc_key = merovingian::crypto::derive_ipc_auth_key(material->bytes());

            THEN("every derivation succeeds — the SecretBuffer-backed span is a drop-in replacement")
            {
                REQUIRE(secret_box_key.has_value());
                REQUIRE(token_key_v4.has_value());
                REQUIRE(token_key_v3.has_value());
                REQUIRE(ipc_key.has_value());
            }
        }

        std::filesystem::remove(path);
    }
}

SCENARIO("Crypto encoding round-trips hex and base64 without embedded null terminators", "[crypto][encoding]")
{
    GIVEN("a known byte sequence")
    {
        auto constexpr input = std::string_view{"hello"};
        auto const input_bytes =
            std::span<unsigned char const>{reinterpret_cast<unsigned char const*>(input.data()), input.size()};

        WHEN("it is hex encoded")
        {
            auto const encoded = merovingian::crypto::to_hex(input_bytes);

            THEN("the result is lowercase hex and has no trailing null")
            {
                REQUIRE(encoded.has_value());
                REQUIRE(*encoded == "68656c6c6f");
                REQUIRE(encoded->find('\0') == std::string::npos);
            }
        }

        WHEN("it is URL-safe base64 encoded and decoded")
        {
            auto const encoded = merovingian::crypto::base64_urlsafe_encode(input);
            auto const decoded = encoded.has_value() ? merovingian::crypto::base64_urlsafe_decode(*encoded)
                                                     : std::optional<std::string>{std::nullopt};

            THEN("the decoded value matches the original and the encoded string has no embedded null")
            {
                REQUIRE(encoded.has_value());
                REQUIRE(encoded->find('\0') == std::string::npos);
                REQUIRE(decoded.has_value());
                REQUIRE(*decoded == input);
            }
        }

        WHEN("it is standard base64 encoded and decoded")
        {
            auto const encoded = merovingian::crypto::base64_original_encode(input);
            auto const decoded = encoded.has_value() ? merovingian::crypto::base64_original_decode(*encoded)
                                                     : std::optional<std::string>{std::nullopt};

            THEN("the decoded value matches the original and the encoded string has no embedded null")
            {
                REQUIRE(encoded.has_value());
                REQUIRE(encoded->find('\0') == std::string::npos);
                REQUIRE(decoded.has_value());
                REQUIRE(*decoded == input);
            }
        }
    }

    GIVEN("invalid base64 input")
    {
        THEN("decoding returns nullopt")
        {
            REQUIRE_FALSE(merovingian::crypto::base64_urlsafe_decode("!!!").has_value());
            REQUIRE_FALSE(merovingian::crypto::base64_original_decode("!!!").has_value());
        }
    }
}

SCENARIO("Crypto generic hash is deterministic and key-separated", "[crypto][hash]")
{
    GIVEN("two calls with the same pieces")
    {
        auto constexpr pieces = std::array<std::string_view, 2>{"alpha", "beta"};
        auto const a = merovingian::crypto::generic_hash(std::span{pieces});
        auto const b = merovingian::crypto::generic_hash(std::span{pieces});

        WHEN("compared")
        {
            THEN("they are identical and have the expected hex length")
            {
                REQUIRE(a.has_value());
                REQUIRE(b.has_value());
                REQUIRE(*a == *b);
                REQUIRE(a->size() == crypto_generichash_BYTES * 2U);
            }
        }
    }

    GIVEN("the same pieces hashed with and without a key")
    {
        auto constexpr pieces = std::array<std::string_view, 2>{"alpha", "beta"};
        auto const key = std::array<std::uint8_t, 16>{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        auto const keyed = merovingian::crypto::generic_hash(std::span{pieces}, std::span{key});
        auto const unkeyed = merovingian::crypto::generic_hash(std::span{pieces});

        WHEN("compared")
        {
            THEN("the keyed digest differs from the unkeyed digest")
            {
                REQUIRE(keyed.has_value());
                REQUIRE(unkeyed.has_value());
                REQUIRE(*keyed != *unkeyed);
            }
        }
    }

    GIVEN("a single contiguous input")
    {
        auto const hex = merovingian::crypto::hash_bytes_to_hex("hello");

        WHEN("hashed to hex")
        {
            THEN("it returns a non-empty hex digest")
            {
                REQUIRE(hex.has_value());
                REQUIRE(hex->size() == crypto_generichash_BYTES * 2U);
            }
        }
    }
}

SCENARIO("RuntimeEd25519Provider signs and verifies with its own keypair", "[crypto][signing]")
{
    GIVEN("a generated Ed25519 keypair")
    {
        auto keypair = merovingian::crypto::generate_ed25519_keypair();
        REQUIRE(keypair.has_value());
        auto provider = merovingian::crypto::RuntimeEd25519Provider{std::move(keypair->secret_key)};
        auto const handle = merovingian::crypto::Ed25519SecretKeyHandle{"ed25519:auto"};
        auto const public_key = merovingian::crypto::Ed25519PublicKey{
            std::string{reinterpret_cast<char const*>(keypair->public_key.data()), keypair->public_key.size()}
        };

        WHEN("a message is signed")
        {
            auto constexpr message = std::string_view{"test message"};
            auto const sign_result = provider.sign(handle, message);

            THEN("the signature is valid against the matching public key")
            {
                REQUIRE(sign_result.signature.bytes.size() == crypto_sign_BYTES);
                auto const verify_result =
                    provider.verify(public_key, message,
                                    merovingian::crypto::Ed25519Signature{std::string{sign_result.signature.bytes}});
                REQUIRE(verify_result.valid);
            }
        }

        WHEN("a different message is presented for verification")
        {
            auto constexpr message = std::string_view{"test message"};
            auto constexpr other = std::string_view{"other message"};
            auto const sign_result = provider.sign(handle, message);
            REQUIRE(sign_result.signature.bytes.size() == crypto_sign_BYTES);
            auto const verify_result = provider.verify(
                public_key, other, merovingian::crypto::Ed25519Signature{std::string{sign_result.signature.bytes}});

            THEN("verification is rejected")
            {
                REQUIRE_FALSE(verify_result.valid);
            }
        }
    }
}

SCENARIO("Crypto random generators return bounded bytes and hex", "[crypto]")
{
    GIVEN("a bounded random request")
    {
        WHEN("random bytes and hex are generated")
        {
            auto const bytes = merovingian::crypto::secure_random_bytes(32U);
            auto const hex = merovingian::crypto::secure_random_hex(16U);

            THEN("the outputs have the expected sizes and hex is lowercase")
            {
                REQUIRE(bytes.has_value());
                REQUIRE(bytes->size() == 32U);
                REQUIRE(hex.has_value());
                REQUIRE(hex->size() == 32U);
                REQUIRE(hex->find_first_not_of("0123456789abcdef") == std::string::npos);
            }
        }
    }

    GIVEN("out-of-bounds random requests")
    {
        THEN("they are rejected")
        {
            REQUIRE_FALSE(merovingian::crypto::secure_random_bytes(0U).has_value());
            REQUIRE_FALSE(merovingian::crypto::secure_random_bytes(4097U).has_value());
            REQUIRE_FALSE(merovingian::crypto::secure_random_hex(0U).has_value());
            REQUIRE_FALSE(merovingian::crypto::secure_random_hex(4097U).has_value());
        }
    }
}

SCENARIO("Crypto encoding helpers reject empty input", "[crypto][encoding]")
{
    GIVEN("empty input")
    {
        auto const empty_bytes = std::span<unsigned char const>{};

        THEN("hex and base64 encoders return nullopt")
        {
            REQUIRE_FALSE(merovingian::crypto::to_hex(empty_bytes).has_value());
            REQUIRE_FALSE(merovingian::crypto::base64_urlsafe_encode("").has_value());
            REQUIRE_FALSE(merovingian::crypto::base64_original_encode("").has_value());
            REQUIRE_FALSE(merovingian::crypto::base64_urlsafe_decode("").has_value());
            REQUIRE_FALSE(merovingian::crypto::base64_original_decode("").has_value());
        }
    }
}

SCENARIO("Crypto generic hash handles empty and non-empty inputs", "[crypto][hash]")
{
    GIVEN("no pieces")
    {
        auto constexpr pieces = std::array<std::string_view, 0>{};
        auto const hash = merovingian::crypto::generic_hash(std::span{pieces});

        THEN("it still returns a valid hex digest")
        {
            REQUIRE(hash.has_value());
            REQUIRE(hash->size() == crypto_generichash_BYTES * 2U);
        }
    }

    GIVEN("an empty contiguous input")
    {
        auto const hash = merovingian::crypto::hash_bytes_to_hex("");

        THEN("it returns a valid hex digest")
        {
            REQUIRE(hash.has_value());
            REQUIRE(hash->size() == crypto_generichash_BYTES * 2U);
        }
    }
}

SCENARIO("Crypto Ed25519 low-level primitives reject invalid material", "[crypto][signing]")
{
    GIVEN("a generated keypair and malformed inputs")
    {
        auto const keypair = merovingian::crypto::generate_ed25519_keypair();
        REQUIRE(keypair.has_value());

        WHEN("the low-level sign function is given the wrong secret-key size")
        {
            auto const bad_secret = std::array<unsigned char, 8>{};
            auto const sign_result = merovingian::crypto::ed25519_sign_detached(std::span{bad_secret}, "message");

            THEN("signing is rejected")
            {
                REQUIRE_FALSE(sign_result.has_value());
            }
        }

        WHEN("verification receives mismatched shapes")
        {
            auto const good_signature =
                merovingian::crypto::ed25519_sign_detached(keypair->secret_key.bytes(), "message");
            REQUIRE(good_signature.has_value());

            auto const bad_public_key = merovingian::crypto::Ed25519PublicKey{std::string(31U, 'p')};
            auto const bad_signature = merovingian::crypto::Ed25519Signature{std::string(63U, 's')};

            auto const bad_key_result = merovingian::crypto::ed25519_verify(bad_public_key, "message", *good_signature);
            auto const bad_sig_result = merovingian::crypto::ed25519_verify(
                merovingian::crypto::Ed25519PublicKey{
                    std::string{reinterpret_cast<char const*>(keypair->public_key.data()), keypair->public_key.size()}
            },
                "message", bad_signature);

            THEN("verification is rejected with a reason")
            {
                REQUIRE_FALSE(bad_key_result.valid);
                REQUIRE_FALSE(bad_key_result.error.empty());
                REQUIRE_FALSE(bad_sig_result.valid);
                REQUIRE_FALSE(bad_sig_result.error.empty());
            }
        }
    }
}

// --- 0.12.5 security audit: signing-secret lifecycle -------------------------
//
// Findings 2, 7 and 16 of security/audit-findings-2026-09-04.md. Every one of
// them is the same defect in a different container: forgery-capable Ed25519
// seed material, or the master key it is encrypted under, sitting in ordinary
// swappable heap memory that is freed without being zeroised.

SCENARIO("A generated Ed25519 keypair holds its secret in locked secret memory", "[crypto][signing][security]")
{
    GIVEN("libsodium is available")
    {
        WHEN("a fresh signing keypair is generated")
        {
            auto const keypair = merovingian::crypto::generate_ed25519_keypair();

            THEN("the secret seed is a SecretBuffer of the libsodium secret-key size, not a plain array")
            {
                REQUIRE(keypair.has_value());
                REQUIRE(keypair->secret_key.bytes().size() == merovingian::crypto::ed25519_secret_key_bytes);
            }

            THEN("the secret seed memory is mlocked so it cannot be paged to swap")
            {
                REQUIRE(keypair.has_value());
                REQUIRE(keypair->secret_key.is_locked());
            }
        }
    }
}

SCENARIO("secret_box_decrypt returns plaintext already inside a SecretBuffer", "[crypto][secret_box][security]")
{
    GIVEN("a derived key and an encrypted signing secret")
    {
        auto const master = std::vector<std::uint8_t>{0x11U, 0x22U, 0x33U, 0x44U};
        auto const key = merovingian::crypto::derive_secret_box_key(master);
        REQUIRE(key.has_value());

        auto const plaintext = std::vector<std::uint8_t>{0xa0U, 0xa1U, 0xa2U, 0xa3U, 0xa4U};
        auto const ciphertext = merovingian::crypto::secret_box_encrypt(plaintext, *key);
        REQUIRE(ciphertext.has_value());

        WHEN("the ciphertext is decrypted")
        {
            auto const decrypted = merovingian::crypto::secret_box_decrypt(*ciphertext, *key);

            THEN("the caller receives the plaintext in mlocked, zeroise-on-destruction memory")
            {
                REQUIRE(decrypted.has_value());
                REQUIRE(decrypted->is_locked());
                REQUIRE(std::equal(decrypted->bytes().begin(), decrypted->bytes().end(), plaintext.begin(),
                                   plaintext.end()));
            }
        }
    }
}

SCENARIO("Master key material is refused when it cannot be locked into memory", "[crypto][master_key][security]")
{
    GIVEN("the fail-closed policy for master key material")
    {
        WHEN("the buffer holding the root secret could not be mlocked")
        {
            auto const accepted = merovingian::crypto::master_key_material_is_acceptable(false);

            THEN("the material is rejected rather than used from swappable memory")
            {
                REQUIRE_FALSE(accepted);
            }
        }

        WHEN("the buffer holding the root secret was successfully mlocked")
        {
            auto const accepted = merovingian::crypto::master_key_material_is_acceptable(true);

            THEN("the material is accepted")
            {
                REQUIRE(accepted);
            }
        }
    }
}

SCENARIO("The multi-key signing provider takes ownership of secrets in locked memory",
         "[crypto][signing][security]")
{
    GIVEN("an Ed25519 keypair whose secret is held in a SecretBuffer")
    {
        auto keypair = merovingian::crypto::generate_ed25519_keypair();
        REQUIRE(keypair.has_value());

        auto const public_key =
            merovingian::crypto::Ed25519PublicKey{std::string{reinterpret_cast<char const*>(
                                                                 keypair->public_key.data()),
                                                             keypair->public_key.size()}};

        auto entries = std::vector<std::pair<std::string, merovingian::core::SecretBuffer>>{};
        entries.emplace_back("ed25519:audit", std::move(keypair->secret_key));

        WHEN("the provider is constructed from those secrets and asked to sign")
        {
            auto provider = merovingian::crypto::RuntimeMultiKeyEd25519Provider{std::move(entries)};
            auto const result = provider.sign(merovingian::crypto::Ed25519SecretKeyHandle{"ed25519:audit"}, "message");

            THEN("the signature verifies against the matching public key")
            {
                REQUIRE(result.error.empty());
                auto const verified = merovingian::crypto::ed25519_verify(public_key, "message", result.signature);
                REQUIRE(verified.valid);
            }
        }

        WHEN("a key id the provider does not hold is requested")
        {
            auto provider = merovingian::crypto::RuntimeMultiKeyEd25519Provider{std::move(entries)};
            auto const result = provider.sign(merovingian::crypto::Ed25519SecretKeyHandle{"ed25519:absent"}, "message");

            THEN("signing fails closed rather than signing with an unrelated key")
            {
                REQUIRE_FALSE(result.error.empty());
                REQUIRE(result.signature.bytes.empty());
            }
        }
    }
}

// --- 0.12.5 security audit, finding 3 ----------------------------------------
//
// encrypt_signing_secret() and decrypt_stored_signing_secret() each re-read the
// master key file and re-derived the secret-box key on every call, so every
// signing-secret operation re-materialised the root secret and churned a 4 KiB
// sodium_mlock/munlock pair. crypto::signing_secret_box_key() caches the derived
// key against the file's identity instead -- the same fix #487 applied to the
// access-token HMAC keys.

SCENARIO("The signing-secret box key is cached rather than re-derived from the master key file",
         "[crypto][master_key][secret_box][security]")
{
    GIVEN("a master key file that has been used once")
    {
        if (::geteuid() == 0U)
        {
            // Root ignores the permission bits, so the unreadable-file lever
            // below would be a no-op and this scenario would pass without
            // proving anything. Skip loudly rather than pass trivially -- some
            // CI jobs run in a container as root.
            SUCCEED("skipped: running as root, where the unreadable-file probe cannot bite");
            return;
        }

        auto const path = write_master_key_file("cache-probe-master-key-material");
        auto const first = merovingian::crypto::signing_secret_box_key(path.string());
        REQUIRE(first.has_value());

        WHEN("the file is made unreadable but its identity is unchanged")
        {
            // stat() still succeeds, so the cached identity still matches, but
            // an open() would now fail. A second call that returned a key can
            // therefore only have come from the cache -- which is exactly the
            // property the finding asks for, observed without a test seam.
            std::filesystem::permissions(path, std::filesystem::perms::none);

            auto const second = merovingian::crypto::signing_secret_box_key(path.string());

            THEN("the same derived key is returned without re-reading the file")
            {
                REQUIRE(second.has_value());
                REQUIRE(second->bytes == first->bytes);
            }

            std::filesystem::permissions(path, std::filesystem::perms::owner_read |
                                                   std::filesystem::perms::owner_write);
        }

        std::filesystem::remove(path);
    }
}

SCENARIO("A replaced master key file invalidates the cached signing-secret box key",
         "[crypto][master_key][secret_box][security]")
{
    GIVEN("a derived key cached from one master key file")
    {
        auto const path = write_master_key_file("original-master-key-material");
        auto const original = merovingian::crypto::signing_secret_box_key(path.string());
        REQUIRE(original.has_value());

        WHEN("the file is replaced with different material")
        {
            // The cache must not outlive the key it was derived from: an
            // operator who rotates the master key expects that to take effect,
            // and a cache keyed on the path alone would serve the retired key
            // indefinitely.
            std::filesystem::remove(path);
            auto const replaced = write_master_key_file("replacement-master-key-material");

            auto const derived = merovingian::crypto::signing_secret_box_key(replaced.string());

            THEN("a different key is derived")
            {
                REQUIRE(derived.has_value());
                REQUIRE(derived->bytes != original->bytes);
            }

            std::filesystem::remove(replaced);
        }
    }
}

SCENARIO("The master key file identity changes when the file's contents are replaced",
         "[crypto][master_key][security]")
{
    GIVEN("a master key file")
    {
        auto const path = write_master_key_file("identity-probe-material");
        auto const identity = merovingian::crypto::master_key_file_identity(path.string());

        WHEN("the identity is read again with no change")
        {
            THEN("it is stable, so the cache is not invalidated on every call")
            {
                REQUIRE_FALSE(identity.empty());
                REQUIRE(merovingian::crypto::master_key_file_identity(path.string()) == identity);
            }
        }

        WHEN("the identity of a path that does not exist is read")
        {
            THEN("it is empty, so an unreadable file never matches a cached entry")
            {
                REQUIRE(merovingian::crypto::master_key_file_identity("/nonexistent/master-key").empty());
            }
        }

        std::filesystem::remove(path);
    }
}

// --- 0.12.5 security audit, finding 20 ---------------------------------------
//
// The loader reads through std::ifstream, whose std::filebuf keeps its own copy
// of every byte read in ordinary heap memory freed without zeroisation -- so
// wiping only our own read buffer still left plaintext root-secret bytes in the
// process. The stream is now unbuffered via pubsetbuf(nullptr, 0) before it is
// opened.
//
// Heap residue cannot be asserted portably. What this covers is that the
// unbuffered read still returns the file's exact bytes across the multi-chunk
// path, which is where an unbuffered stream would most plausibly go wrong.

SCENARIO("The unbuffered master key loader returns exact bytes across chunk boundaries",
         "[crypto][master_key][security]")
{
    GIVEN("master key files spanning one, several and the maximum number of read chunks")
    {
        // The loader reads in 1024-byte chunks. Distinct content per chunk
        // catches an unbuffered read that drops, duplicates or reorders one.
        auto content = std::string{};
        for (auto chunk = 0U; chunk < 4U; ++chunk)
        {
            content.append(std::string(1024U, static_cast<char>('a' + chunk)));
        }
        REQUIRE(content.size() == 4096U);

        WHEN("a file spanning exactly four chunks is loaded")
        {
            auto const path = write_master_key_file(content);
            auto const material = merovingian::crypto::load_master_key_material(path.string());

            THEN("every byte of every chunk survives in order")
            {
                REQUIRE(material.has_value());
                REQUIRE(material->bytes().size() == content.size());
                REQUIRE(std::equal(material->bytes().begin(), material->bytes().end(), content.begin(), content.end(),
                                   [](std::uint8_t lhs, char rhs) noexcept {
                                       return lhs == static_cast<std::uint8_t>(rhs);
                                   }));
            }

            std::filesystem::remove(path);
        }

        WHEN("a file straddling a chunk boundary by one byte is loaded")
        {
            auto const straddling = content.substr(0U, 1025U);
            auto const path = write_master_key_file(straddling);
            auto const material = merovingian::crypto::load_master_key_material(path.string());

            THEN("the trailing partial chunk is neither truncated nor padded")
            {
                REQUIRE(material.has_value());
                REQUIRE(material->bytes().size() == 1025U);
                REQUIRE(material->bytes().back() == static_cast<std::uint8_t>('b'));
            }

            std::filesystem::remove(path);
        }
    }
}

// --- 0.12.5 audit, finding 17: the sanctioned way to erase secret bytes ------
//
// core::secure_zero is what modules outside the crypto boundary use to clear a
// buffer that held secret material, since they must not call libsodium
// directly. It is reached in production through
// database::PersistentServerSigningKey, but the primitive is worth pinning on
// its own: a version that silently did nothing would leave no trace at the call
// sites that depend on it.

SCENARIO("secure_zero erases a buffer in place", "[core][secret_buffer][security]")
{
    GIVEN("a buffer holding recognisable secret bytes")
    {
        auto secret = std::string{"master-key-material"};

        WHEN("it is erased through secure_zero")
        {
            merovingian::core::secure_zero(std::as_writable_bytes(std::span{secret}));

            THEN("every byte is zero, and none of the original content survives")
            {
                REQUIRE(std::ranges::all_of(secret, [](char c) {
                    return c == '\0';
                }));
                REQUIRE(secret.find("master-key") == std::string::npos);
            }
        }
    }

    GIVEN("an empty buffer")
    {
        auto empty = std::string{};

        WHEN("it is erased")
        {
            THEN("the call is a no-op rather than dereferencing a null data pointer")
            {
                merovingian::core::secure_zero(std::as_writable_bytes(std::span{empty}));
                REQUIRE(empty.empty());
            }
        }
    }
}

SCENARIO("The signing-secret box key is unavailable when no master key path is configured",
         "[crypto][master_key][security]")
{
    GIVEN("an empty master key path, as an unconfigured server has")
    {
        WHEN("the signing-secret box key is requested")
        {
            auto const key = merovingian::crypto::signing_secret_box_key("");

            THEN("no key is produced, so the caller cannot encrypt or decrypt a signing secret")
            {
                REQUIRE_FALSE(key.has_value());
            }
        }
    }

    GIVEN("a master key path that does not exist")
    {
        WHEN("the signing-secret box key is requested")
        {
            auto const key = merovingian::crypto::signing_secret_box_key("/nonexistent/merovingian-master-key");

            THEN("no key is produced")
            {
                REQUIRE_FALSE(key.has_value());
            }
        }
    }
}
