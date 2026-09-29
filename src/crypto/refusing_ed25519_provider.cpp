// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/crypto/refusing_ed25519_provider.hpp"

namespace merovingian::crypto
{

auto RefusingEd25519Provider::sign(Ed25519SecretKeyHandle const& /*key*/,
                                   std::string_view /*message*/) -> SignatureResult
{
    return {{}, "signing is not permitted in this process: the federation worker holds no signing capability"};
}

auto RefusingEd25519Provider::verify(Ed25519PublicKey const& /*public_key*/, std::string_view /*message*/,
                                     Ed25519Signature const& /*signature*/) -> VerificationResult
{
    return {false, "verification is not permitted in this process: the federation worker holds no signing capability"};
}

} // namespace merovingian::crypto
