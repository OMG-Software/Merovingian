// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <array>
#include <string>
#include <string_view>

#include <sodium.h>

namespace merovingian::federation::test
{

struct SigningKeypair final
{
    std::string public_key{}; // raw 32-byte Ed25519 public key
    std::string secret_key{}; // raw 64-byte Ed25519 secret key
};

// Derives a deterministic Ed25519 keypair from a seed string. Tests pair a
// signed federation request (signed with secret_key) against the remote key
// record that verifies it (carrying public_key), so both sides must come from
// the same seed. Real federation uses randomly generated keys; the seed only
// keeps test expectations reproducible.
[[nodiscard]] inline auto keypair_from_seed(std::string_view seed_text) -> SigningKeypair
{
    static_cast<void>(sodium_init());
    auto seed = std::array<unsigned char, crypto_sign_SEEDBYTES>{};
    crypto_generichash(seed.data(), seed.size(), reinterpret_cast<unsigned char const*>(seed_text.data()),
                       seed_text.size(), nullptr, 0U);
    auto public_key = std::array<unsigned char, crypto_sign_PUBLICKEYBYTES>{};
    auto secret_key = std::array<unsigned char, crypto_sign_SECRETKEYBYTES>{};
    crypto_sign_seed_keypair(public_key.data(), secret_key.data(), seed.data());
    return {std::string{reinterpret_cast<char const*>(public_key.data()), public_key.size()},
            std::string{reinterpret_cast<char const*>(secret_key.data()), secret_key.size()}};
}

} // namespace merovingian::federation::test
