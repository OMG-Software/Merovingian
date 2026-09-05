// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/crypto/runtime_ed25519_provider.hpp"

#include <utility>

#include <sodium.h>

namespace merovingian::crypto
{

RuntimeEd25519Provider::RuntimeEd25519Provider(core::SecretBuffer secret_key)
    : secret_key_{std::move(secret_key)}
{
}

auto RuntimeEd25519Provider::sign(Ed25519SecretKeyHandle const& /*key*/, std::string_view message) -> SignatureResult
{
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
