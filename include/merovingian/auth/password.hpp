// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::auth
{

// Argon2id-hash a password using libsodium's interactive limits. The returned
// string is safe to keep in memory and to compare with password_matches.
[[nodiscard]] auto hash_password(std::string_view password) -> std::optional<std::string>;

// Constant-time verify a password against an Argon2id hash produced by hash_password.
[[nodiscard]] auto password_matches(std::string_view password_hash, std::string_view password) noexcept -> bool;

// Argon2id-hash a registration token. Empty tokens are rejected so the failure is
// obvious rather than producing a predictable hash.
[[nodiscard]] auto hash_registration_token(std::span<std::uint8_t const> token) -> std::optional<std::string>;

// Constant-time verify a presented registration token against an Argon2id hash
// produced by hash_registration_token.
[[nodiscard]] auto registration_token_matches(std::string_view expected_hash, std::string_view presented) noexcept
    -> bool;

} // namespace merovingian::auth
