// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace merovingian::crypto
{

struct Ed25519PublicKey final
{
    std::string bytes{};
};

struct Ed25519SecretKeyHandle final
{
    std::string key_id{};
};

struct Ed25519Signature final
{
    std::string bytes{};
};

struct Ed25519Keypair final
{
    std::array<std::uint8_t, 32U> public_key{};
    std::array<std::uint8_t, 64U> secret_key{};
};

struct SignatureResult final
{
    Ed25519Signature signature{};
    std::string error{};
};

struct VerificationResult final
{
    bool valid{false};
    std::string error{};
};

class Ed25519Provider
{
public:
    Ed25519Provider() = default;
    Ed25519Provider(Ed25519Provider const& other) = delete;
    auto operator=(Ed25519Provider const& other) -> Ed25519Provider& = delete;
    Ed25519Provider(Ed25519Provider&& other) noexcept = delete;
    auto operator=(Ed25519Provider&& other) noexcept -> Ed25519Provider& = delete;
    virtual ~Ed25519Provider() = default;

    [[nodiscard]] virtual auto sign(Ed25519SecretKeyHandle const& key, std::string_view message) -> SignatureResult = 0;
    [[nodiscard]] virtual auto verify(Ed25519PublicKey const& public_key, std::string_view message,
                                      Ed25519Signature const& signature) -> VerificationResult = 0;
};

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
