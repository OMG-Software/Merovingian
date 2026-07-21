// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/auth/identity.hpp"
#include "merovingian/auth/password.hpp"
#include "merovingian/auth/token.hpp"
#include "merovingian/crypto/token_key.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <chrono>
#include <span>

SCENARIO("Auth identity validators enforce Matrix-shaped identifiers", "[auth]")
{
    GIVEN("valid and invalid Matrix identity strings")
    {
        auto constexpr valid_user = "@alice:example.org";
        auto constexpr invalid_user = "alice:example.org";
        auto constexpr valid_device = "DEVICE123";
        auto constexpr invalid_device = "DEVICE 123";

        WHEN("identity values are validated")
        {
            auto const valid_user_result = merovingian::auth::user_id_is_valid(valid_user);
            auto const invalid_user_result = merovingian::auth::user_id_is_valid(invalid_user);
            auto const valid_device_result = merovingian::auth::device_id_is_valid(valid_device);
            auto const invalid_device_result = merovingian::auth::device_id_is_valid(invalid_device);

            THEN("only Matrix-shaped values are accepted")
            {
                REQUIRE(valid_user_result);
                REQUIRE_FALSE(invalid_user_result);
                REQUIRE(valid_device_result);
                REQUIRE_FALSE(invalid_device_result);
            }
        }
    }
}

SCENARIO("Auth server-name validator rejects malformed host and port shapes", "[auth]")
{
    GIVEN("valid and malformed server names")
    {
        auto constexpr valid_hostname = "example.org";
        auto constexpr valid_hostname_with_port = "example.org:8448";
        auto constexpr valid_ipv6_with_port = "[2001:db8::1]:8448";
        auto constexpr missing_hostname = ":8448";
        auto constexpr missing_port = "example.org:";
        auto constexpr non_numeric_port = "example.org:abc";
        auto constexpr repeated_colon = "example.org:8448:443";

        WHEN("server names are validated")
        {
            auto const valid_hostname_result = merovingian::auth::server_name_is_valid(valid_hostname);
            auto const valid_hostname_with_port_result =
                merovingian::auth::server_name_is_valid(valid_hostname_with_port);
            auto const valid_ipv6_with_port_result = merovingian::auth::server_name_is_valid(valid_ipv6_with_port);
            auto const missing_hostname_result = merovingian::auth::server_name_is_valid(missing_hostname);
            auto const missing_port_result = merovingian::auth::server_name_is_valid(missing_port);
            auto const non_numeric_port_result = merovingian::auth::server_name_is_valid(non_numeric_port);
            auto const repeated_colon_result = merovingian::auth::server_name_is_valid(repeated_colon);

            THEN("only structured host and optional numeric port values are accepted")
            {
                REQUIRE(valid_hostname_result);
                REQUIRE(valid_hostname_with_port_result);
                REQUIRE(valid_ipv6_with_port_result);
                REQUIRE_FALSE(missing_hostname_result);
                REQUIRE_FALSE(missing_port_result);
                REQUIRE_FALSE(non_numeric_port_result);
                REQUIRE_FALSE(repeated_colon_result);
            }
        }
    }
}

SCENARIO("Auth user ID validator enforces lowercase-only localparts for new IDs", "[auth]")
{
    GIVEN("a lowercase-only user ID, an uppercase user ID, and a malformed server name")
    {
        auto constexpr valid_user = "@alice_1.-=/+:example.org";
        auto constexpr uppercase_user = "@Alice:example.org";
        auto constexpr malformed_server_user = "@alice:example.org:abc";

        WHEN("user IDs are validated with the strict new-ID validator")
        {
            auto const valid_user_result = merovingian::auth::user_id_is_valid(valid_user);
            auto const uppercase_user_result = merovingian::auth::user_id_is_valid(uppercase_user);
            auto const malformed_server_user_result = merovingian::auth::user_id_is_valid(malformed_server_user);

            THEN("lowercase localparts are accepted; uppercase and malformed server names are rejected")
            {
                // New-ID path: lowercase + allowed punctuation is valid.
                REQUIRE(valid_user_result);
                // New-ID path: uppercase localpart is rejected — spec restricts new IDs to a-z.
                // Do NOT change to REQUIRE — accepting uppercase at registration creates
                // ambiguous identifiers and breaks future case-folding.
                REQUIRE_FALSE(uppercase_user_result);
                // Malformed server name is always rejected.
                REQUIRE_FALSE(malformed_server_user_result);
            }
        }

        WHEN("the uppercase user ID is validated with the federated validator")
        {
            auto const fed_result = merovingian::auth::user_id_is_valid_federated(uppercase_user);

            THEN("it is accepted — historical IDs are valid for federation paths")
            {
                // The federated validator accepts historical uppercase localparts.
                // Use this on inbound federation, not on local registration.
                REQUIRE(fed_result);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.18 §"Account suspension"
// URL: ../../docs/matrix-v1.18-spec/client-server-api.md#account-suspension
// Suspended users SHOULD be permitted to log in and create additional sessions
// (which are themselves suspended); only locked accounts are denied a new login.
SCENARIO("Auth login policy blocks locked accounts but permits suspended login", "[auth]")
{
    GIVEN("active, locked, and suspended users")
    {
        auto active = merovingian::auth::UserIdentity{"@alice:example.org"};
        auto locked = merovingian::auth::UserIdentity{"@bob:example.org", merovingian::auth::AccountState::locked};
        auto suspended =
            merovingian::auth::UserIdentity{"@carol:example.org", merovingian::auth::AccountState::suspended};

        WHEN("login policy is evaluated")
        {
            auto const active_decision = merovingian::auth::login_policy(active);
            auto const locked_decision = merovingian::auth::login_policy(locked);
            auto const suspended_decision = merovingian::auth::login_policy(suspended);

            THEN("active and suspended accounts may proceed; only locked is denied")
            {
                // Spec MUST: locked accounts are denied a new login.
                REQUIRE(active_decision.allowed);
                REQUIRE_FALSE(locked_decision.allowed);
                REQUIRE(locked_decision.reason == "account locked");
                // Spec SHOULD: suspended users may log in; the new session is
                // itself suspended and enforced by the request-path gate.
                REQUIRE(suspended_decision.allowed);
                REQUIRE(suspended_decision.reason.empty());
            }
        }
    }
}

SCENARIO("Auth password policy requires a hardened minimum shape", "[auth]")
{
    GIVEN("weak and stronger password candidates")
    {
        auto constexpr weak_password = "password";
        auto constexpr stronger_password = "CorrectHorse7!";

        WHEN("password policy is evaluated")
        {
            auto const weak_accepted = merovingian::auth::password_is_acceptable(weak_password);
            auto const stronger_accepted = merovingian::auth::password_is_acceptable(stronger_password);

            THEN("weak passwords are rejected")
            {
                REQUIRE_FALSE(weak_accepted);
                REQUIRE(stronger_accepted);
            }
        }
    }
}

SCENARIO("Auth token policy accepts only active hashed tokens", "[auth][tokens]")
{
    GIVEN("an active token and revoked or expired variants")
    {
        auto const now = std::chrono::system_clock::now();
        auto active = merovingian::auth::AccessTokenRecord{
            "@alice:example.org",
            "DEVICE123",
            merovingian::auth::TokenHash{"external-kdf", "abcdefghijklmnopqrstuvwxyz0123456789"},
            now + std::chrono::hours{1},
            false,
        };
        auto revoked = active;
        revoked.revoked = true;
        auto expired = active;
        expired.expires_at = now - std::chrono::seconds{1};

        WHEN("token policy is evaluated")
        {
            auto const active_decision = merovingian::auth::token_is_active(active, now);
            auto const revoked_decision = merovingian::auth::token_is_active(revoked, now);
            auto const expired_decision = merovingian::auth::token_is_active(expired, now);

            THEN("only the active hashed token is accepted")
            {
                REQUIRE(active_decision.accepted);
                REQUIRE_FALSE(revoked_decision.accepted);
                REQUIRE_FALSE(expired_decision.accepted);
                REQUIRE(revoked_decision.reason == "token revoked");
                REQUIRE(expired_decision.reason == "token expired");
            }
        }
    }
}

SCENARIO("Auth token helpers avoid plaintext token disclosure", "[auth][tokens]")
{
    GIVEN("a plaintext token secret")
    {
        auto constexpr token_secret = "0123456789abcdefghijklmnopqrstuvwxyz";

        WHEN("the token is redacted and compared")
        {
            auto const redacted = merovingian::auth::redacted_token_for_log(token_secret);
            auto const matching = merovingian::auth::constant_time_equal(token_secret, token_secret);
            auto const different =
                merovingian::auth::constant_time_equal(token_secret, "different-token-secret-000000000000");

            THEN("logs contain only a coarse size bucket, not the exact length or the token itself")
            {
                // #437: the exact byte length is a minor side channel (it
                // distinguishes token versions and valid- from
                // invalid-length presented tokens); redaction now discloses
                // only a coarse size bucket.
                REQUIRE(redacted.find(token_secret) == std::string::npos);
                REQUIRE(redacted == "[redacted-token:size=short]");
                REQUIRE(matching);
                REQUIRE_FALSE(different);
            }
        }
    }
}

SCENARIO("Auth variable-length constant-time compare hides secret length", "[auth][tokens][security]")
{
    GIVEN("plaintext secrets of differing lengths")
    {
        WHEN("compared with the variable-length helper")
        {
            auto const matching = merovingian::auth::constant_time_equal_variable_length("alpha", "alpha");
            auto const different_same_length = merovingian::auth::constant_time_equal_variable_length("alpha", "betaa");
            auto const different_length = merovingian::auth::constant_time_equal_variable_length("alpha", "alphabet");
            auto const empty_vs_value = merovingian::auth::constant_time_equal_variable_length("", "alpha");

            THEN("only exact content matches are accepted")
            {
                REQUIRE(matching);
                REQUIRE_FALSE(different_same_length);
                REQUIRE_FALSE(different_length);
                REQUIRE_FALSE(empty_vs_value);
            }
        }
    }
}

SCENARIO("Auth password hashing round-trips through Argon2id verification", "[auth][password][slow]")
{
    GIVEN("a plaintext password")
    {
        auto constexpr plaintext = "CorrectHorseBatteryStaple7!";

        WHEN("it is hashed and verified")
        {
            auto const hash = merovingian::auth::hash_password(plaintext);

            THEN("the hash is non-empty, differs from the plaintext, and verifies correctly")
            {
                REQUIRE(hash.has_value());
                REQUIRE_FALSE(hash->empty());
                REQUIRE(*hash != plaintext);
                REQUIRE(merovingian::auth::password_matches(*hash, plaintext));
                REQUIRE_FALSE(merovingian::auth::password_matches(*hash, "wrong-password"));
            }
        }
    }
}

// Regression test for #434: crypto_pwhash_str_verify's first argument must
// be a null-terminated C string, but password_matches passed
// string_view::data() directly. Every caller today passes a std::string, so
// the call happens to be safe — this constructs the exact latent scenario
// the issue describes: a hash string_view sliced out of a larger buffer,
// where the byte immediately after the slice is not a null terminator.
SCENARIO("Auth password matching is safe with a non-null-terminated string_view slice", "[auth][password][security]")
{
    GIVEN("a password hash embedded in a larger buffer, viewed through a non-null-terminated slice")
    {
        auto constexpr plaintext = "CorrectHorseBatteryStaple7!";
        auto const hash = merovingian::auth::hash_password(plaintext);
        REQUIRE(hash.has_value());

        // The byte right after the slice boundary is 'T', not '\0'.
        auto const buffer = *hash + std::string{"TRAILING-NON-HASH-BYTES-NO-NULL-HERE"};
        auto const sliced_hash = std::string_view{buffer}.substr(0U, hash->size());

        WHEN("the sliced hash is verified against the correct password")
        {
            auto const result = merovingian::auth::password_matches(sliced_hash, plaintext);

            THEN("verification still succeeds — the implementation copies into a null-terminated buffer first")
            {
                REQUIRE(result);
            }
        }
    }
}

// Same latent-buffer-shape regression as above, for registration_token_matches.
SCENARIO("Auth registration token matching is safe with a non-null-terminated string_view slice",
         "[auth][tokens][security]")
{
    GIVEN("a registration token hash embedded in a larger buffer, viewed through a non-null-terminated slice")
    {
        auto const token =
            std::array<unsigned char, 32>{0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15,
                                          16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
        auto const hash = merovingian::auth::hash_registration_token(std::span{token});
        REQUIRE(hash.has_value());

        auto const buffer = *hash + std::string{"TRAILING-NON-HASH-BYTES-NO-NULL-HERE"};
        auto const sliced_hash = std::string_view{buffer}.substr(0U, hash->size());
        auto const presented_token = std::string{reinterpret_cast<char const*>(token.data()), token.size()};

        WHEN("the sliced hash is verified against the correct token")
        {
            auto const result = merovingian::auth::registration_token_matches(sliced_hash, presented_token);

            THEN("verification still succeeds — the implementation copies into a null-terminated buffer first")
            {
                REQUIRE(result);
            }
        }
    }
}

SCENARIO("Auth token helpers classify secrets, hashes, and access tokens", "[auth][tokens]")
{
    GIVEN("token secrets of varying entropy")
    {
        THEN("only secrets with at least 32 bytes are accepted")
        {
            REQUIRE(merovingian::auth::token_secret_has_required_entropy("0123456789abcdefghijklmnopqrstuvwxyz"));
            REQUIRE_FALSE(merovingian::auth::token_secret_has_required_entropy("short"));
            REQUIRE_FALSE(merovingian::auth::token_secret_has_required_entropy(std::string(4097U, 'x')));
        }
    }

    GIVEN("token hashes with and without required fields")
    {
        THEN("persistence requires a non-empty algorithm and value")
        {
            REQUIRE(merovingian::auth::token_hash_is_persistable(
                merovingian::auth::TokenHash{"external-kdf", "abcdefghijklmnopqrstuvwxyz0123456789"}));
            REQUIRE_FALSE(merovingian::auth::token_hash_is_persistable(merovingian::auth::TokenHash{"", "value"}));
            REQUIRE_FALSE(merovingian::auth::token_hash_is_persistable(merovingian::auth::TokenHash{"algo", ""}));
            REQUIRE_FALSE(merovingian::auth::token_hash_is_persistable(
                merovingian::auth::TokenHash{"algo", std::string(31U, 'x')}));
        }
    }

    GIVEN("a plaintext access token and an HMAC key")
    {
        auto constexpr token = "0123456789abcdefghijklmnopqrstuvwxyz";
        auto key = merovingian::crypto::TokenHmacKey{};
        key.bytes.fill(0xAB);

        WHEN("it is hashed under each supported version")
        {
            auto const v2 = merovingian::auth::hash_access_token_v2(token);
            auto const v3 = merovingian::auth::hash_access_token_v3(token, key);
            auto const v4 = merovingian::auth::hash_access_token_v4(token, key);

            THEN("each version produces a distinct, prefixed hash and rejects empty tokens")
            {
                REQUIRE(v2.has_value());
                REQUIRE(v2->starts_with("token-hash:v2:"));
                REQUIRE(v3.has_value());
                REQUIRE(v3->starts_with("token-hash:v3:"));
                REQUIRE(v4.has_value());
                REQUIRE(v4->starts_with("token-hash:v4:"));
                REQUIRE(*v3 != *v4);
                REQUIRE_FALSE(merovingian::auth::hash_access_token_v2("").has_value());
                REQUIRE_FALSE(merovingian::auth::hash_access_token_v3("", key).has_value());
                REQUIRE_FALSE(merovingian::auth::hash_access_token_v4("", key).has_value());
            }
        }
    }
}

SCENARIO("Auth password matching rejects malformed inputs", "[auth][password]")
{
    GIVEN("empty inputs and a legacy hash")
    {
        auto constexpr plaintext = "CorrectHorseBatteryStaple7!";

        WHEN("password_matches is called with malformed arguments")
        {
            auto const result = merovingian::auth::password_matches("", plaintext);

            THEN("it returns false without attempting verification")
            {
                REQUIRE_FALSE(result);
                REQUIRE_FALSE(merovingian::auth::password_matches("some-hash", ""));
                // A hash without the v2 prefix is still passed to libsodium for verification.
                REQUIRE_FALSE(merovingian::auth::password_matches("not-a-password-hash", plaintext));
            }
        }
    }
}

SCENARIO("Auth registration token hashing round-trips", "[auth][tokens][slow]")
{
    GIVEN("a registration token")
    {
        auto const token =
            std::array<unsigned char, 32>{0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15,
                                          16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};

        WHEN("it is hashed and verified")
        {
            auto const hash = merovingian::auth::hash_registration_token(std::span{token});

            THEN("the hash is non-empty and verifies only the original token")
            {
                REQUIRE(hash.has_value());
                REQUIRE_FALSE(hash->empty());
                REQUIRE(merovingian::auth::registration_token_matches(
                    *hash, std::string{reinterpret_cast<char const*>(token.data()), token.size()}));
                REQUIRE_FALSE(merovingian::auth::registration_token_matches(*hash, "wrong-token"));
            }
        }
    }
}
