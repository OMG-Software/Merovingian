// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/crypto/ed25519.hpp"

#include <string_view>

namespace merovingian::crypto
{

// Ed25519Provider for a process that must never sign or verify: the
// out-of-process federation worker (ADR-0078, superseding the signing part of
// ADR-0015). It holds no key material and forwards nothing to anyone, so a
// compromised worker has no signing capability to abuse, locally or through
// main. Every request fails closed with a clear error; nothing ever falls
// back to a weaker operation or terminates the process.
class RefusingEd25519Provider final : public Ed25519Provider
{
public:
    [[nodiscard]] auto sign(Ed25519SecretKeyHandle const& key, std::string_view message) -> SignatureResult override;
    [[nodiscard]] auto verify(Ed25519PublicKey const& public_key, std::string_view message,
                              Ed25519Signature const& signature) -> VerificationResult override;
};

} // namespace merovingian::crypto
