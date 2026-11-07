// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/crypto/secure_key_bytes.hpp"

namespace merovingian::crypto
{

// A 32-byte symmetric key suitable for libsodium's crypto_secretbox.
//
// Secret material must not survive past its scope (core/AGENTS.md): the
// destructor zeroises `bytes` with sodium_memzero, and copies/moves zeroise
// whichever instance is left behind rather than relying on the caller.
struct SecretBoxKey final
{
    SecureKeyBytes bytes{};

    SecretBoxKey() = default;
    SecretBoxKey(SecretBoxKey const&) = default;
    auto operator=(SecretBoxKey const&) -> SecretBoxKey& = default;
    SecretBoxKey(SecretBoxKey&&) noexcept = default;
    auto operator=(SecretBoxKey&&) noexcept -> SecretBoxKey& = default;
    ~SecretBoxKey() = default;
};

} // namespace merovingian::crypto
