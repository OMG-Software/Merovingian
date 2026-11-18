// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

namespace merovingian::crypto
{

// The size of a SHA-256 digest, in bytes.
inline constexpr std::size_t sha256_digest_bytes = 32U;

// The SHA-256 digest of `input` as 32 raw bytes (libsodium's crypto_hash_sha256). For a protocol that names SHA-256
// (PKCE `S256`, a Content-Security-Policy hash source); a hash this project chooses for itself uses generic_hash.
// Returns std::nullopt only when libsodium cannot be initialised. An empty input is hashed like any other.
[[nodiscard]] auto sha256(std::string_view input) -> std::optional<std::string>;

} // namespace merovingian::crypto
