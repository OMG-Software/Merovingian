// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

#include <sodium.h>

namespace merovingian::crypto
{

// 32-byte HMAC key derived from operator-supplied master key material using a
// domain-separated libsodium generic hash. This key is used for access-token
// hashing and must never be reused for signing-secret encryption.
struct TokenHmacKey final
{
    std::array<unsigned char, crypto_generichash_KEYBYTES> bytes{};
};

// Derive an independent access-token HMAC key from master key material.
// The same input material always produces the same derived key so tokens hashed
// on one startup remain verifiable after restart. Returns nullopt if libsodium
// is not initialised or the material is empty. This is the current (v4) scheme.
[[nodiscard]] auto derive_token_hmac_key(std::span<std::uint8_t const> master_key_material) noexcept
    -> std::optional<TokenHmacKey>;

// Derive the legacy v3 access-token HMAC key from master key material using a
// distinct domain-separation label from the v4 key. Issue #322 moved the legacy
// v3 key off the Ed25519 signing seed (which violated key separation) onto a
// master-key-derived key. Existing stored v3 token hashes are invalidated by
// this change; affected sessions must re-login and are upgraded to v4. Returns
// nullopt if no master key is configured (fail-closed, same shape as v4).
[[nodiscard]] auto derive_token_hmac_key_v3(std::span<std::uint8_t const> master_key_material) noexcept
    -> std::optional<TokenHmacKey>;

} // namespace merovingian::crypto
