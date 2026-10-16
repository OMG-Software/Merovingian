// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/crypto/secure_key_bytes.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string_view>

#include <sodium.h>

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

static_assert(SecureKeyBytes::key_bytes == crypto_generichash_KEYBYTES);

// Both access-token HMAC keys, derived together from one read of the master key.
struct TokenHmacKeys final
{
    std::optional<TokenHmacKey> v3{};
    std::optional<TokenHmacKey> v4{};
};

// The token HMAC keys derived from the master key file at `path`, cached
// against that file's identity (ISO-7: identity and bytes from one open).
//
// CRY-4, PR #509 review: these keys are on every authenticated request's path.
// A cache hit costs one open and fstat and shares the cached, locked keys; it
// never copies them, because every copy is a fresh locked allocation and the
// per-request copies could exhaust RLIMIT_MEMLOCK under concurrency.
//
// nullptr when `path` is empty, or the file is unreadable, insecure, invalid or
// cannot be locked into memory. An unreadable file is logged once per outage,
// not once per request. Thread-safe.
[[nodiscard]] auto cached_token_hmac_keys(std::string_view path)
    -> std::shared_ptr<TokenHmacKeys const>; // SHARED_PTR: reviewed — locked keys shared by readers

} // namespace merovingian::crypto
