// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/crypto/RuntimeEd25519Provider.hpp"

#include "merovingian/crypto/Ed25519Keypair.hpp"
#include "merovingian/crypto/Ed25519.hpp"

#include <sodium.h>

#include <utility>

namespace merovingian::crypto
{

RuntimeEd25519Provider::RuntimeEd25519Provider(core::SecretBuffer secret_key)
{
    // Security audit 2026-09 L-07: reject (by not retaining) a secret that is
    // not exactly the 64-byte Ed25519 secret key representation. `secret_key_`
    // stays at its empty in-class default; `secret_key` is wiped by
    // SecretBuffer's destructor when this constructor returns.
    if (secret_key.bytes().size() == ed25519_secret_key_bytes)
    {
        secret_key_ = std::move(secret_key);
    }
}

auto RuntimeEd25519Provider::sign(Ed25519SecretKeyHandle const& /*key*/, std::string_view message) -> SignatureResult
{
    // Security audit 2026-09 M-07: never hand libsodium a buffer that is not
    // exactly the 64-byte Ed25519 secret key representation. Defense in depth
    // alongside the constructor guard above (L-07); matches the size guard
    // RuntimeMultiKeyEd25519Provider::sign applies to its stored keys.
    if (secret_key_.bytes().size() != ed25519_secret_key_bytes)
    {
        return {{}, "signing key is not a valid Ed25519 secret key"};
    }

    auto signature = std::string(64U, '\0');
    if (crypto_sign_detached(reinterpret_cast<unsigned char*>(signature.data()), nullptr,
                             reinterpret_cast<unsigned char const*>(message.data()), message.size(),
                             secret_key_.bytes().data()) != 0)
    {
        return {{}, "Ed25519 signing failed"};
    }
    return {Ed25519Signature{std::move(signature)}, {}};
}

auto RuntimeEd25519Provider::verify(Ed25519PublicKey const& public_key, std::string_view message,
                                    Ed25519Signature const& signature) -> VerificationResult
{
    return ed25519_verify(public_key, message, signature);
}

} // namespace merovingian::crypto
