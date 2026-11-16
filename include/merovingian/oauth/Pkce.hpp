// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <string_view>

namespace merovingian::oauth
{

// Proof Key for Code Exchange (RFC 7636), method `S256` only: `plain` is never accepted (ADR-0768).

// The only `code_challenge_method` accepted.
inline constexpr std::string_view pkce_method_s256 = "S256";

// A `code_challenge` is BASE64URL(SHA256(verifier)) without padding: always 43 characters.
inline constexpr std::size_t pkce_challenge_chars = 43U;
// RFC 7636 section 4.1: a `code_verifier` is 43 to 128 characters.
inline constexpr std::size_t pkce_verifier_min_chars = 43U;
inline constexpr std::size_t pkce_verifier_max_chars = 128U;

// Whether `challenge` can be an S256 challenge: exactly 43 base64url characters (`A-Z a-z 0-9 - _`), no padding,
// and a last character whose two unused low bits are zero, so it is the one encoding of a 32-byte digest. A
// challenge no verifier can match is refused when the authorisation request arrives, not at the token endpoint.
[[nodiscard]] auto pkce_challenge_is_valid(std::string_view challenge) noexcept -> bool;

// Whether `verifier` is a valid `code_verifier`: 43 to 128 characters of `A-Z a-z 0-9 - . _ ~` (RFC 7636 section 4.1).
[[nodiscard]] auto pkce_verifier_is_valid(std::string_view verifier) noexcept -> bool;

// Whether BASE64URL(SHA256(verifier)) equals `challenge`, compared in constant time. False when either input is
// invalid by the two checks above, or when hashing fails.
[[nodiscard]] auto pkce_s256_matches(std::string_view verifier, std::string_view challenge) -> bool;

} // namespace merovingian::oauth
