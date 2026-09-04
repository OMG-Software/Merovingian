// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/core/secret_buffer.hpp"
#include "merovingian/crypto/ed25519.hpp"

#include <cstddef>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace merovingian::crypto
{

// Production Ed25519Provider implementation that can sign with more than one
// active Ed25519 key at a time. Each key is keyed by its Matrix key_id
// ("ed25519:<version>"). The signing primitive looks up the key_id supplied
// in the Ed25519SecretKeyHandle and rejects the request if that key is not
// held, so multiple simultaneously-active server signing keys stay isolated.
//
// Secrets are owned as core::SecretBuffer, so every held seed is mlocked
// against swap and zeroised when the provider is replaced during key rotation
// rather than being left as residue in freed heap memory.
class RuntimeMultiKeyEd25519Provider final : public Ed25519Provider
{
public:
    explicit RuntimeMultiKeyEd25519Provider(std::vector<std::pair<std::string, core::SecretBuffer>> keys);

    [[nodiscard]] auto sign(Ed25519SecretKeyHandle const& key, std::string_view message) -> SignatureResult override;
    [[nodiscard]] auto verify(Ed25519PublicKey const& public_key, std::string_view message,
                              Ed25519Signature const& signature) -> VerificationResult override;

private:
    std::unordered_map<std::string, core::SecretBuffer> secrets_{};
};

} // namespace merovingian::crypto
