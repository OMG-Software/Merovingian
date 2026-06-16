// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

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

// A 32-byte symmetric key suitable for libsodium's crypto_secretbox.
// The bytes are secret material and must be cleared on destruction.
struct SecretBoxKey final
{
    std::array<std::uint8_t, 32U> bytes{};
};

// Nonce + XSalsa20-Poly1305 ciphertext, stored as raw bytes (caller encodes
// to base64 or another printable form).
struct SecretBoxCiphertext final
{
    std::vector<std::uint8_t> bytes{}; // nonce || mac || ciphertext
};

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
[[nodiscard]] auto secret_box_decrypt(SecretBoxCiphertext const& ciphertext, SecretBoxKey const& key)
    -> std::optional<std::vector<std::uint8_t>>;

// Prefix stored in the database to distinguish encrypted secrets from legacy
// plaintext base64 secrets.  Legacy rows have no prefix and are decrypted by
// treating the whole column as base64 Ed25519 secret bytes.
constexpr auto secret_box_storage_prefix = std::string_view{"secretbox:v1:"};

} // namespace merovingian::crypto
