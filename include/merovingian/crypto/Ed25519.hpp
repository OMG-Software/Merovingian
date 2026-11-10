// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/core/SecretBuffer.hpp"
#include "merovingian/crypto/Ed25519Keypair.hpp"
#include "merovingian/crypto/Ed25519PublicKey.hpp"
#include "merovingian/crypto/Ed25519Signature.hpp"
#include "merovingian/crypto/VerificationResult.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace merovingian::crypto
{

[[nodiscard]] auto ed25519_public_key_shape_is_valid(Ed25519PublicKey const& public_key) noexcept -> bool;
[[nodiscard]] auto ed25519_signature_shape_is_valid(Ed25519Signature const& signature) noexcept -> bool;
[[nodiscard]] auto ed25519_key_id_is_valid(std::string_view key_id) noexcept -> bool;

// Generate a fresh Ed25519 signing keypair. The secret key is the 64-byte
// libsodium representation (seed || public key). Returns std::nullopt if
// libsodium is unavailable or key generation fails.
[[nodiscard]] auto generate_ed25519_keypair() -> std::optional<Ed25519Keypair>;

// Stateless Ed25519 verification against an arbitrary public key — no signing key
// store or provider is required, unlike Ed25519Provider::sign. Used to verify
// signatures made by parties outside the federation trust store (e.g. an identity
// server's third-party-invite token signature), as well as by the production
// Ed25519Provider implementation for federation/event signature checks.
[[nodiscard]] auto ed25519_verify(Ed25519PublicKey const& public_key, std::string_view message,
                                  Ed25519Signature const& signature) noexcept -> VerificationResult;

// Sign a message with a raw 64-byte libsodium Ed25519 secret key. This is the
// low-level primitive used by RuntimeEd25519Provider; callers that have a provider
// should prefer Ed25519Provider::sign so the key never leaves the provider.
[[nodiscard]] auto ed25519_sign_detached(std::span<unsigned char const> secret_key, std::string_view message)
    -> std::optional<Ed25519Signature>;

} // namespace merovingian::crypto
