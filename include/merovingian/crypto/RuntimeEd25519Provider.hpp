// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/core/SecretBuffer.hpp"
#include "merovingian/crypto/Ed25519Provider.hpp"
#include "merovingian/crypto/Ed25519PublicKey.hpp"
#include "merovingian/crypto/Ed25519SecretKeyHandle.hpp"
#include "merovingian/crypto/Ed25519Signature.hpp"
#include "merovingian/crypto/SignatureResult.hpp"
#include "merovingian/crypto/VerificationResult.hpp"

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
    // Security audit 2026-09 L-07: this is the trust boundary where
    // forgery-capable secret material enters the provider, so it is
    // validated here rather than left to the first sign() call. A
    // SecretBuffer that is not exactly ed25519_secret_key_bytes (64 bytes)
    // is never retained -- the constructor leaves secret_key_ at its empty
    // default and the malformed bytes are wiped when the by-value parameter
    // goes out of scope. Construction itself cannot report an error (this
    // project's toolchain does not build std::expected cleanly, and
    // Ed25519Provider deletes copy/move, ruling out an optional-returning
    // factory that would need to relocate the constructed object); sign()
    // (M-07) carries its own guard on the stored buffer's size, so a
    // provider built from bad key material can never produce a signature
    // either way.
    explicit RuntimeEd25519Provider(core::SecretBuffer secret_key);

    [[nodiscard]] auto sign(Ed25519SecretKeyHandle const& /*key*/, std::string_view message)
        -> SignatureResult override;
    [[nodiscard]] auto verify(Ed25519PublicKey const& public_key, std::string_view message,
                              Ed25519Signature const& signature) -> VerificationResult override;

private:
    core::SecretBuffer secret_key_{};
};

} // namespace merovingian::crypto
