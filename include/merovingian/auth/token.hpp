// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <chrono>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

namespace merovingian::crypto
{

struct TokenHmacKey;

} // namespace merovingian::crypto

namespace merovingian::auth
{

[[nodiscard]] auto constant_time_equal(std::string_view left, std::string_view right) noexcept -> bool;
[[nodiscard]] auto constant_time_equal_variable_length(std::string_view left, std::string_view right) noexcept -> bool;

// Hash a v2 access token with an unkeyed libsodium generichash. The returned
// string is the hex digest prefixed with "token-hash:v2:".
[[nodiscard]] auto hash_access_token_v2(std::string_view token) -> std::optional<std::string>;

// Hash an access token with a v3 master-key-derived HMAC key.
[[nodiscard]] auto hash_access_token_v3(std::string_view token, merovingian::crypto::TokenHmacKey const& key)
    -> std::optional<std::string>;

// Hash an access token with a v4 master-key-derived HMAC key.
[[nodiscard]] auto hash_access_token_v4(std::string_view token, merovingian::crypto::TokenHmacKey const& key)
    -> std::optional<std::string>;

} // namespace merovingian::auth
