// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/crypto/SecureKeyBytes.hpp"

namespace merovingian::crypto
{

// 32-byte HMAC key derived from operator-supplied master key material using a
// domain-separated libsodium generic hash. This key is used for access-token
// hashing and must never be reused for signing-secret encryption.
//
// Secret material must not survive past its scope (core/AGENTS.md): the
// destructor zeroises `bytes` with sodium_memzero, and copies/moves zeroise
// whichever instance is left behind rather than relying on the caller.
struct TokenHmacKey final
{
    SecureKeyBytes bytes{};

    TokenHmacKey() = default;
    TokenHmacKey(TokenHmacKey const&) = default;
    auto operator=(TokenHmacKey const&) -> TokenHmacKey& = default;
    TokenHmacKey(TokenHmacKey&&) noexcept = default;
    auto operator=(TokenHmacKey&&) noexcept -> TokenHmacKey& = default;
    ~TokenHmacKey() = default;
};

} // namespace merovingian::crypto
