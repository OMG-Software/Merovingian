// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/crypto/runtime_multikey_ed25519_provider.hpp"

#include <algorithm>
#include <utility>

#include <sodium.h>

namespace merovingian::crypto
{

RuntimeMultiKeyEd25519Provider::RuntimeMultiKeyEd25519Provider(
    std::vector<std::pair<std::string, std::array<unsigned char, 64U>>> keys)
{
    for (auto&& entry : keys)
    {
        secrets_.insert_or_assign(std::move(entry.first), std::move(entry.second));
    }
}

auto RuntimeMultiKeyEd25519Provider::sign(Ed25519SecretKeyHandle const& key, std::string_view message)
    -> SignatureResult
{
    auto const it = secrets_.find(key.key_id);
    if (it == secrets_.end())
    {
        return {{}, "signing key not held: " + key.key_id};
    }

    auto signature = std::string(64U, '\0');
    if (crypto_sign_detached(reinterpret_cast<unsigned char*>(signature.data()), nullptr,
                             reinterpret_cast<unsigned char const*>(message.data()), message.size(),
                             it->second.data()) != 0)
    {
        return {{}, "Ed25519 signing failed"};
    }
    return {Ed25519Signature{std::move(signature)}, {}};
}

auto RuntimeMultiKeyEd25519Provider::verify(Ed25519PublicKey const& public_key, std::string_view message,
                                            Ed25519Signature const& signature) -> VerificationResult
{
    return ed25519_verify(public_key, message, signature);
}

} // namespace merovingian::crypto
