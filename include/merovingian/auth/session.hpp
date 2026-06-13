// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/auth/identity.hpp"
#include "merovingian/auth/token.hpp"

#include <chrono>
#include <string>
#include <string_view>

namespace merovingian::auth
{

enum class ClientAuthEndpoint
{
    login,
    logout,
    logout_all,
    register_account,
    refresh_token,
    list_devices,
    get_device,
    update_device,
    delete_device,
};

struct RegistrationPolicy final
{
    bool enabled{false};
    bool require_token{true};
    bool token_present{false};
};

struct RegistrationPolicyDecision final
{
    bool allowed{false};
    std::string reason{};
};

struct SessionRecord final
{
    std::string user_id{};
    std::string device_id{};
    AccessTokenRecord access_token{};
    bool device_deleted{false};
    bool global_logout_generation_revoked{false};
};

struct SessionInvalidationDecision final
{
    bool active{false};
    std::string reason{};
};

struct ClientAuthAuditEvent final
{
    std::string event_type{};
    std::string user_id{};
    std::string device_id{};
    std::string outcome{};
    std::string reason{};
};

[[nodiscard]] auto client_auth_endpoint_name(ClientAuthEndpoint endpoint) noexcept -> char const*;
[[nodiscard]] auto client_auth_endpoint_requires_access_token(ClientAuthEndpoint endpoint) noexcept -> bool;
[[nodiscard]] auto client_auth_endpoint_mutates_session(ClientAuthEndpoint endpoint) noexcept -> bool;
[[nodiscard]] auto registration_policy(RegistrationPolicy policy) -> RegistrationPolicyDecision;
[[nodiscard]] auto session_is_active(SessionRecord const& session, std::chrono::system_clock::time_point now)
    -> SessionInvalidationDecision;
[[nodiscard]] auto make_client_auth_audit_event(ClientAuthEndpoint endpoint, std::string_view user_id,
                                                std::string_view device_id, bool allowed, std::string_view reason)
    -> ClientAuthAuditEvent;
[[nodiscard]] auto client_auth_audit_summary(ClientAuthAuditEvent const& event) -> std::string;

} // namespace merovingian::auth
