// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>
#include <string_view>

namespace merovingian::auth
{

enum class AccountState
{
    active,
    locked,
    suspended,
};

struct UserIdentity final
{
    std::string user_id{};
    AccountState state{AccountState::active};
    bool password_login_enabled{true};
    bool admin{false};
};

struct DeviceIdentity final
{
    std::string user_id{};
    std::string device_id{};
    std::string display_name{};
};

struct LoginPolicyDecision final
{
    bool allowed{false};
    std::string reason{};
};

[[nodiscard]] auto server_name_is_valid(std::string_view server_name) noexcept -> bool;

// Validates a localpart for a NEW user ID (registration / local auth paths).
// Accepts: a-z, 0-9, '.', '_', '-', '=', '/', '+'. Non-empty required.
// Rejects uppercase — new IDs must be lowercase per Matrix v1.18 spec.
[[nodiscard]] auto localpart_is_valid_new(std::string_view localpart) noexcept -> bool;

// Validates a localpart received over FEDERATION from a historical deployment.
// Accepts: any valid UTF-8 code point that is not ':' or NUL and is not a
// surrogate (U+D800–U+DFFF). Empty localparts are accepted for compatibility.
[[nodiscard]] auto localpart_is_valid_federated(std::string_view localpart) noexcept -> bool;

// Validates a full user ID for local/registration paths (strict localpart rules).
[[nodiscard]] auto user_id_is_valid(std::string_view user_id) noexcept -> bool;

// Validates a full user ID received over federation (historical localpart rules).
[[nodiscard]] auto user_id_is_valid_federated(std::string_view user_id) noexcept -> bool;

[[nodiscard]] auto device_id_is_valid(std::string_view device_id) noexcept -> bool;
[[nodiscard]] auto password_is_acceptable(std::string_view password) noexcept -> bool;
[[nodiscard]] auto login_policy(UserIdentity const& user) -> LoginPolicyDecision;

} // namespace merovingian::auth
