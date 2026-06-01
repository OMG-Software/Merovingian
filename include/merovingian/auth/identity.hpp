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
[[nodiscard]] auto localpart_is_valid(std::string_view localpart) noexcept -> bool;
[[nodiscard]] auto user_id_is_valid(std::string_view user_id) noexcept -> bool;
[[nodiscard]] auto device_id_is_valid(std::string_view device_id) noexcept -> bool;
[[nodiscard]] auto password_is_acceptable(std::string_view password) noexcept -> bool;
[[nodiscard]] auto login_policy(UserIdentity const& user) -> LoginPolicyDecision;

} // namespace merovingian::auth
