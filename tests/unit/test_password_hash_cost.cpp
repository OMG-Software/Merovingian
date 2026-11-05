// SPDX-License-Identifier: GPL-3.0-or-later
//
// The test binaries hash at minimum cost, and only ever in place of the cost production asks for (ADR-0510).
// tests/password_cost/ proves the production cost in a binary without this override.

#include "../support/password_hash_cost.hpp"
#include "merovingian/auth/password.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include <sodium.h>

namespace
{

[[nodiscard]] auto without_prefix(std::string const& stored) -> std::string
{
    auto constexpr prefix = std::string_view{"password-hash:v2:"};
    return stored.starts_with(prefix) ? stored.substr(prefix.size()) : stored;
}

[[nodiscard]] auto has_cost(std::string const& hash, unsigned long long opslimit, std::size_t memlimit) -> bool
{
    return crypto_pwhash_str_needs_rehash(hash.c_str(), opslimit, memlimit) == 0;
}

[[nodiscard]] auto has_minimum_cost(std::string const& hash) -> bool
{
    return has_cost(hash, crypto_pwhash_argon2id_OPSLIMIT_MIN, crypto_pwhash_argon2id_MEMLIMIT_MIN);
}

[[nodiscard]] auto has_production_cost(std::string const& hash) -> bool
{
    return has_cost(hash, crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE);
}

} // namespace

SCENARIO("The test binaries hash passwords at minimum cost through the production code", "[auth][password-cost]")
{
    GIVEN("an initialised libsodium")
    {
        REQUIRE(sodium_init() >= 0);

        WHEN("the production code hashes a password")
        {
            auto const stored = merovingian::auth::hash_password("correct horse");

            THEN("the hash has the minimum cost and is still a real Argon2id hash of that password")
            {
                REQUIRE(stored.has_value());
                REQUIRE(has_minimum_cost(without_prefix(*stored)));
                REQUIRE(stored->starts_with("password-hash:v2:$argon2id$"));
                REQUIRE(merovingian::auth::password_matches(*stored, "correct horse"));
                REQUIRE_FALSE(merovingian::auth::password_matches(*stored, "wrong horse"));
            }
        }

        WHEN("the production code hashes a registration token")
        {
            auto const token = std::array<std::uint8_t, 4U>{1U, 2U, 3U, 4U};
            auto const stored = merovingian::auth::hash_registration_token(token);

            THEN("the hash has the minimum cost")
            {
                REQUIRE(stored.has_value());
                REQUIRE(has_minimum_cost(*stored));
            }
        }
    }
}

SCENARIO("A password hash at any cost but production's is refused in the test binaries", "[auth][password-cost]")
{
    GIVEN("an initialised libsodium")
    {
        REQUIRE(sodium_init() >= 0);
        auto output = std::array<char, crypto_pwhash_STRBYTES>{};
        auto constexpr password = std::string_view{"correct horse"};

        WHEN("the cost asked for is lower than production's, as a downgrade would be")
        {
            auto const result = crypto_pwhash_str(output.data(), password.data(), password.size(),
                                                  crypto_pwhash_OPSLIMIT_MIN, crypto_pwhash_MEMLIMIT_MIN);

            THEN("no hash is made, so everything that registers or logs in fails")
            {
                REQUIRE(result != 0);
            }
        }

        WHEN("only the memory cost differs")
        {
            auto const result = crypto_pwhash_str(output.data(), password.data(), password.size(),
                                                  crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_MIN);

            THEN("no hash is made")
            {
                REQUIRE(result != 0);
            }
        }

        WHEN("only the operations cost differs, even while a scenario holds the real cost")
        {
            auto const real_cost = merovingian::tests::RealPasswordHashCost{};
            auto const result = crypto_pwhash_str(output.data(), password.data(), password.size(),
                                                  crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_INTERACTIVE);

            THEN("no hash is made")
            {
                REQUIRE(result != 0);
            }
        }
    }
}

SCENARIO("A scenario can hold the real password hash cost", "[auth][password-cost]")
{
    GIVEN("an initialised libsodium")
    {
        REQUIRE(sodium_init() >= 0);

        WHEN("a scenario holds the real cost")
        {
            auto stored = std::optional<std::string>{};
            {
                auto const outer = merovingian::tests::RealPasswordHashCost{};
                {
                    auto const inner = merovingian::tests::RealPasswordHashCost{};
                }
                stored = merovingian::auth::hash_password("correct horse");
            }
            auto const after = merovingian::auth::hash_password("correct horse");

            THEN("the hash has production's cost until the last holder lets go")
            {
                REQUIRE(stored.has_value());
                REQUIRE(has_production_cost(without_prefix(*stored)));
                REQUIRE(merovingian::auth::password_matches(*stored, "correct horse"));
                REQUIRE(after.has_value());
                REQUIRE(has_minimum_cost(without_prefix(*after)));
            }
        }
    }
}
