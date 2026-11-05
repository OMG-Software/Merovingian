// SPDX-License-Identifier: GPL-3.0-or-later
//
// The other test binaries hash at minimum cost (ADR-0510). This one is linked without that override, so it sees
// what the shipped server does.

#include "merovingian/auth/password.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstdint>
#include <string>
#include <string_view>

#include <sodium.h>

SCENARIO("The production code hashes at libsodium's interactive Argon2id cost", "[auth][password-cost]")
{
    GIVEN("an initialised libsodium and no override of the hash")
    {
        REQUIRE(sodium_init() >= 0);

        WHEN("a password is hashed")
        {
            auto const stored = merovingian::auth::hash_password("correct horse");

            THEN("the stored hash has the interactive cost and verifies only that password")
            {
                REQUIRE(stored.has_value());
                REQUIRE(stored->starts_with("password-hash:v2:$argon2id$"));
                auto const hash = stored->substr(std::string_view{"password-hash:v2:"}.size());
                REQUIRE(crypto_pwhash_str_needs_rehash(hash.c_str(), crypto_pwhash_OPSLIMIT_INTERACTIVE,
                                                       crypto_pwhash_MEMLIMIT_INTERACTIVE) == 0);
                REQUIRE(merovingian::auth::password_matches(*stored, "correct horse"));
                REQUIRE_FALSE(merovingian::auth::password_matches(*stored, "wrong horse"));
            }
        }

        WHEN("a registration token is hashed")
        {
            auto const token = std::array<std::uint8_t, 4U>{1U, 2U, 3U, 4U};
            auto const stored = merovingian::auth::hash_registration_token(token);

            THEN("the stored hash has the interactive cost")
            {
                REQUIRE(stored.has_value());
                REQUIRE(crypto_pwhash_str_needs_rehash(stored->c_str(), crypto_pwhash_OPSLIMIT_INTERACTIVE,
                                                       crypto_pwhash_MEMLIMIT_INTERACTIVE) == 0);
            }
        }
    }
}
