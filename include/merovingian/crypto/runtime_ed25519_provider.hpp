// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/core/secret_buffer.hpp"
#include "merovingian/crypto/ed25519.hpp"

#include <cstddef>

namespace merovingian::crypto
{

// Production Ed25519Provider implementation backed by a 64-byte libsodium
// secret key. Holds the secret for the lifetime of the object so signing does
// not repeatedly copy the key. The signing primitive itself is confined to
// src/crypto/ so the homeserver module never calls libsodium directly.
//
// The secret is owned as a core::SecretBuffer: a plain std::array member would
// keep forgery-capable seed material in ordinary, swappable, never-zeroised
// process memory for the whole life of the provider.
class RuntimeEd25519Provider final : public Ed25519Provider
{
public:
    explicit RuntimeEd25519Provider(core::SecretBuffer secret_key);

    [[nodiscard]] auto sign(Ed25519SecretKeyHandle const& /*key*/, std::string_view message)
        -> SignatureResult override;
    [[nodiscard]] auto verify(Ed25519PublicKey const& public_key, std::string_view message,
                              Ed25519Signature const& signature) -> VerificationResult override;

private:
    core::SecretBuffer secret_key_{};
};

} // namespace merovingian::crypto
