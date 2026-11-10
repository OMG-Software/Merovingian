// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "SigningKeypair.hpp"

#include "merovingian/crypto/Ed25519Provider.hpp"
#include "merovingian/crypto/Ed25519PublicKey.hpp"
#include "merovingian/crypto/Ed25519SecretKeyHandle.hpp"
#include "merovingian/crypto/Ed25519Signature.hpp"
#include "merovingian/crypto/SignatureResult.hpp"
#include "merovingian/crypto/VerificationResult.hpp"

#include <sodium.h>

#include <array>
#include <string>
#include <string_view>
#include <utility>

namespace merovingian::federation::test
{

// An Ed25519 provider that signs with the keypair derived from a seed, for
// sign_event_for_server in PDU verification tests. It never verifies.
class TestEd25519Provider final : public merovingian::crypto::Ed25519Provider
{
public:
    explicit TestEd25519Provider(std::string key_material)
        : key_material_{std::move(key_material)}
    {
    }

    [[nodiscard]] auto sign(merovingian::crypto::Ed25519SecretKeyHandle const&, std::string_view message)
        -> merovingian::crypto::SignatureResult override
    {
        auto kp = keypair_from_seed(key_material_);
        auto sig = std::array<unsigned char, crypto_sign_BYTES>{};
        crypto_sign_detached(sig.data(), nullptr, reinterpret_cast<unsigned char const*>(message.data()),
                             message.size(), reinterpret_cast<unsigned char const*>(kp.secret_key.data()));
        return {
            merovingian::crypto::Ed25519Signature{std::string{reinterpret_cast<char const*>(sig.data()), sig.size()}},
            {}};
    }

    [[nodiscard]] auto verify(merovingian::crypto::Ed25519PublicKey const&, std::string_view,
                              merovingian::crypto::Ed25519Signature const&)
        -> merovingian::crypto::VerificationResult override
    {
        return {false, "test provider does not verify"};
    }

private:
    std::string key_material_{};
};

} // namespace merovingian::federation::test
