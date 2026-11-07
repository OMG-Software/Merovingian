// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/crypto/Ed25519PublicKey.hpp"
#include "merovingian/crypto/Ed25519SecretKeyHandle.hpp"
#include "merovingian/crypto/Ed25519Signature.hpp"
#include "merovingian/crypto/SignatureResult.hpp"
#include "merovingian/crypto/VerificationResult.hpp"

#include <string_view>

namespace merovingian::crypto
{

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

} // namespace merovingian::crypto
