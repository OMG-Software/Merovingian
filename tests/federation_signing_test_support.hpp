// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/core/secret_buffer.hpp"
#include "merovingian/events/event_signer.hpp"

#include <array>
#include <cstdint>
#include <span>
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

// Signs `payload` with the Ed25519 secret key and returns the unpadded base64
// encoded signature. Suitable for constructing OTK / fallback key payloads.
[[nodiscard]] inline auto sign_payload_b64(std::string_view payload, std::string const& secret_key_bytes) -> std::string
{
    auto sig = std::array<unsigned char, crypto_sign_BYTES>{};
    crypto_sign_detached(sig.data(), nullptr, reinterpret_cast<unsigned char const*>(payload.data()), payload.size(),
                         reinterpret_cast<unsigned char const*>(secret_key_bytes.data()));
    return merovingian::events::matrix_base64_from_bytes(
        {reinterpret_cast<char const*>(sig.data()), crypto_sign_BYTES});
}

// Builds a complete signed_curve25519 OTK JSON value (no wrapping key-id object).
// The signature covers the canonical JSON payload {"key":"key_value"}.
// Use the same keypair's public key (via pubkey_b64()) in the device_keys upload.
[[nodiscard]] inline auto make_signed_otk_json(std::string_view user_id, std::string_view device_id,
                                               std::string_view key_value, std::string const& secret_key_bytes)
    -> std::string
{
    auto const payload = std::string{R"({"key":")"} + std::string{key_value} + R"("})";
    auto const sig_b64 = sign_payload_b64(payload, secret_key_bytes);
    return std::string{R"({"key":")"} + std::string{key_value} + R"(","signatures":{")" + std::string{user_id} +
           R"(":{"ed25519:)" + std::string{device_id} + R"(":")" + sig_b64 + R"("}}})";
}

// Builds a complete signed fallback key JSON value (includes "fallback":true).
// The signature covers {"fallback":true,"key":"key_value"} (canonical field order).
// Use the same keypair's public key in the device_keys upload.
[[nodiscard]] inline auto make_signed_fallback_key_json(std::string_view user_id, std::string_view device_id,
                                                        std::string_view key_value, std::string const& secret_key_bytes)
    -> std::string
{
    // "fallback" sorts before "key" in canonical JSON.
    auto const payload = std::string{R"({"fallback":true,"key":")"} + std::string{key_value} + R"("})";
    auto const sig_b64 = sign_payload_b64(payload, secret_key_bytes);
    return std::string{R"({"fallback":true,"key":")"} + std::string{key_value} + R"(","signatures":{")" +
           std::string{user_id} + R"(":{"ed25519:)" + std::string{device_id} + R"(":")" + sig_b64 + R"("}}})";
}

} // namespace merovingian::federation::test
