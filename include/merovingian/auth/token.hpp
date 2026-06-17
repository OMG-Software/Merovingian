// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <chrono>
#include <cstddef>
#include <string>
#include <string_view>

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

} // namespace merovingian::auth
