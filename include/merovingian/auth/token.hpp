// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <chrono>
#include <cstddef>
#include <string>
#include <string_view>

namespace merovingian::crypto
{

struct TokenHmacKey;

} // namespace merovingian::crypto

namespace merovingian::auth
{

struct TokenHash final
{
    std::string algorithm{"unimplemented-external-kdf"};
    std::string value{};
};

struct AccessTokenRecord final
{
    std::string user_id{};
    std::string device_id{};
    TokenHash token_hash{};
    std::chrono::system_clock::time_point expires_at{};
    bool revoked{false};
};

struct TokenPolicyDecision final
{
    bool accepted{false};
    std::string reason{};
};

[[nodiscard]] auto token_secret_has_required_entropy(std::string_view token_secret) noexcept -> bool;
[[nodiscard]] auto token_hash_is_persistable(TokenHash const& token_hash) noexcept -> bool;
[[nodiscard]] auto token_is_active(AccessTokenRecord const& token, std::chrono::system_clock::time_point now)
    -> TokenPolicyDecision;
[[nodiscard]] auto constant_time_equal(std::string_view left, std::string_view right) noexcept -> bool;
[[nodiscard]] auto constant_time_equal_variable_length(std::string_view left, std::string_view right) noexcept -> bool;
[[nodiscard]] auto redacted_token_for_log(std::string_view token_secret) -> std::string;

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
