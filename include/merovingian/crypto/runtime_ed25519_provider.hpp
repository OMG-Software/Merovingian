// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/crypto/ed25519.hpp"

#include <array>
#include <cstddef>

namespace merovingian::crypto
{

// Production Ed25519Provider implementation backed by a 64-byte libsodium
// secret key. Holds the secret for the lifetime of the object so signing does
// not repeatedly copy the key. The signing primitive itself is confined to
// src/crypto/ so the homeserver module never calls libsodium directly.
class RuntimeEd25519Provider final : public Ed25519Provider
{
public:
    explicit RuntimeEd25519Provider(std::array<unsigned char, 64U> secret_key);

    [[nodiscard]] auto sign(Ed25519SecretKeyHandle const& /*key*/, std::string_view message)
        -> SignatureResult override;
    [[nodiscard]] auto verify(Ed25519PublicKey const& public_key, std::string_view message,
                              Ed25519Signature const& signature) -> VerificationResult override;

private:
    std::array<unsigned char, 64U> secret_key_{};
};

} // namespace merovingian::crypto
