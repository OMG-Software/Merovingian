// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/core/SecretBuffer.hpp"
#include "merovingian/crypto/SecretBoxCiphertext.hpp"
#include "merovingian/crypto/SecretBoxKey.hpp"
#include "merovingian/crypto/SecureKeyBytes.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::crypto
{

// Derive a SecretBoxKey from operator-supplied master key material using a
// domain-separated libsodium generic hash.  The same input material always
// produces the same derived key so the server can decrypt after restart.
[[nodiscard]] auto derive_secret_box_key(std::span<std::uint8_t const> master_key_material) noexcept
    -> std::optional<SecretBoxKey>;

// Encrypt `plaintext` with the given key.  Returns nullopt if libsodium is not
// initialised or the plaintext is empty.  The output includes a random nonce
// and the Poly1305 authentication tag.
[[nodiscard]] auto secret_box_encrypt(std::span<std::uint8_t const> plaintext, SecretBoxKey const& key)
    -> std::optional<SecretBoxCiphertext>;

// Decrypt a ciphertext produced by secret_box_encrypt.  Returns nullopt if the
// ciphertext is too short, corrupted, or the authentication tag does not match.
//
// The plaintext is returned in a core::SecretBuffer, not a std::vector: what
// this function decrypts is the server signing secret, and an intermediate
// vector would leave a forgery-capable copy in freed, unwiped heap memory
// between the decrypt and the caller's own SecretBuffer.
[[nodiscard]] auto secret_box_decrypt(SecretBoxCiphertext const& ciphertext, SecretBoxKey const& key)
    -> std::optional<core::SecretBuffer>;

// Prefix stored in the database to distinguish encrypted secrets from legacy
// plaintext base64 secrets.  Legacy rows have no prefix and are decrypted by
// treating the whole column as base64 Ed25519 secret bytes.
constexpr auto secret_box_storage_prefix = std::string_view{"secretbox:v1:"};

} // namespace merovingian::crypto
