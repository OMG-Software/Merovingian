// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/crypto/ed25519.hpp"

#include <algorithm>

#include <sodium.h>

namespace merovingian::crypto
{
namespace
{

    [[nodiscard]] auto is_printable_without_space(char value) noexcept -> bool
    {
        auto const byte = static_cast<unsigned char>(value);
        return byte > 0x20U && byte < 0x7FU;
    }

} // namespace

auto ed25519_public_key_shape_is_valid(Ed25519PublicKey const& public_key) noexcept -> bool
{
    return public_key.bytes.size() == 32U;
}

auto ed25519_signature_shape_is_valid(Ed25519Signature const& signature) noexcept -> bool
{
    return signature.bytes.size() == 64U;
}

auto ed25519_key_id_is_valid(std::string_view key_id) noexcept -> bool
{
    auto constexpr prefix = std::string_view{"ed25519:"};
    return key_id.size() > prefix.size() && key_id.size() <= 255U && key_id.starts_with(prefix) &&
           std::ranges::all_of(key_id.substr(prefix.size()), is_printable_without_space);
}

auto ed25519_verify(Ed25519PublicKey const& public_key, std::string_view message,
                    Ed25519Signature const& signature) noexcept -> VerificationResult
{
    if (!ed25519_public_key_shape_is_valid(public_key) || !ed25519_signature_shape_is_valid(signature))
    {
        return {false, "invalid Ed25519 material"};
    }
    auto const ok = crypto_sign_verify_detached(reinterpret_cast<unsigned char const*>(signature.bytes.data()),
                                                reinterpret_cast<unsigned char const*>(message.data()), message.size(),
                                                reinterpret_cast<unsigned char const*>(public_key.bytes.data())) == 0;
    return {ok, ok ? std::string{} : std::string{"signature verification failed"}};
}

auto generate_ed25519_keypair() -> std::optional<Ed25519Keypair>
{
    static auto const ready = sodium_init() >= 0;
    if (!ready)
    {
        return std::nullopt;
    }
    auto keypair = Ed25519Keypair{};
    keypair.secret_key = core::SecretBuffer{ed25519_secret_key_bytes};
    // Generate straight into the locked buffer. Writing to a stack array first
    // and copying would leave an unwiped duplicate of the seed behind.
    if (crypto_sign_keypair(keypair.public_key.data(), keypair.secret_key.bytes().data()) != 0)
    {
        return std::nullopt;
    }
    return keypair;
}

auto ed25519_sign_detached(std::span<unsigned char const> secret_key, std::string_view message)
    -> std::optional<Ed25519Signature>
{
    static auto const ready = sodium_init() >= 0;
    if (!ready || secret_key.size() != 64U)
    {
        return std::nullopt;
    }
    auto signature = std::string(64U, '\0');
    if (crypto_sign_detached(reinterpret_cast<unsigned char*>(signature.data()), nullptr,
                             reinterpret_cast<unsigned char const*>(message.data()), message.size(),
                             secret_key.data()) != 0)
    {
        return std::nullopt;
    }
    return Ed25519Signature{std::move(signature)};
}

} // namespace merovingian::crypto
