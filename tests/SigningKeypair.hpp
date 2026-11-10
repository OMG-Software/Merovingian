// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/core/SecretBuffer.hpp"
#include "merovingian/events/EventId.hpp"

#include <sodium.h>

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <tuple>

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
    std::ignore = sodium_init();
    auto seed = std::array<unsigned char, crypto_sign_SEEDBYTES>{};
    crypto_generichash(seed.data(), seed.size(), reinterpret_cast<unsigned char const*>(seed_text.data()),
                       seed_text.size(), nullptr, 0U);
    auto public_key = std::array<unsigned char, crypto_sign_PUBLICKEYBYTES>{};
    auto secret_key = std::array<unsigned char, crypto_sign_SECRETKEYBYTES>{};
    crypto_sign_seed_keypair(public_key.data(), secret_key.data(), seed.data());
    return {
        std::string{reinterpret_cast<char const*>(public_key.data()), public_key.size()},
        std::string{reinterpret_cast<char const*>(secret_key.data()), secret_key.size()}
    };
}

// Returns the unpadded Matrix base64 encoding of the keypair's public key,
// ready to be stored in the "ed25519:DEVICE_ID" field of a device_keys upload.
[[nodiscard]] inline auto pubkey_b64(SigningKeypair const& kp) -> std::string
{
    return merovingian::events::matrix_base64_from_bytes(kp.public_key);
}

// Returns a non-owning span over the keypair's raw 64-byte Ed25519 secret key.
// The caller MUST keep `kp` alive for as long as the span is used — e.g. across
// a synchronous build_outbound_request call where the OutboundCall borrows it.
// Used by tests that wire OutboundCall::secret_key (now a span) without
// materialising an unpinned std::string copy of the key.
[[nodiscard]] inline auto secret_key_span(SigningKeypair const& kp) -> std::span<std::uint8_t const>
{
    return {reinterpret_cast<std::uint8_t const*>(kp.secret_key.data()), kp.secret_key.size()};
}

// Copies the keypair's raw 64-byte Ed25519 secret key into an owning, mlocked,
// zeroised SecretBuffer — the shape production uses for DispatchWorkerConfig and
// the runtime signing key. The caller no longer needs to keep `kp` alive after
// this returns, because the SecretBuffer holds its own copy of the bytes.
[[nodiscard]] inline auto secret_key_buffer(SigningKeypair const& kp) -> core::SecretBuffer
{
    return core::SecretBuffer{secret_key_span(kp)};
}

} // namespace merovingian::federation::test
