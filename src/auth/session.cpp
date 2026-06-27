// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/auth/session.hpp"

#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"

#include <string>
#include <vector>

namespace merovingian::auth
{
namespace
{

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields,
                        observability::LogEventSeverity severity = observability::LogEventSeverity::debug) -> void
    {
        observability::log_diagnostic("session", event, fields, severity);
    }

} // namespace

auto client_auth_endpoint_name(ClientAuthEndpoint endpoint) noexcept -> char const*
{
    switch (endpoint)
    {
    case ClientAuthEndpoint::login:
        return "login";
    case ClientAuthEndpoint::logout:
        return "logout";
    case ClientAuthEndpoint::logout_all:
        return "logout_all";
    case ClientAuthEndpoint::register_account:
        return "register";
    case ClientAuthEndpoint::refresh_token:
        return "refresh_token";
    case ClientAuthEndpoint::list_devices:
        return "list_devices";
    case ClientAuthEndpoint::get_device:
        return "get_device";
    case ClientAuthEndpoint::update_device:
        return "update_device";
    case ClientAuthEndpoint::delete_device:
        return "delete_device";
    }

    return "unknown";
}

auto client_auth_endpoint_requires_access_token(ClientAuthEndpoint endpoint) noexcept -> bool
{
    return endpoint != ClientAuthEndpoint::login && endpoint != ClientAuthEndpoint::register_account;
}

auto client_auth_endpoint_mutates_session(ClientAuthEndpoint endpoint) noexcept -> bool
{
    return endpoint == ClientAuthEndpoint::login || endpoint == ClientAuthEndpoint::logout ||
           endpoint == ClientAuthEndpoint::logout_all || endpoint == ClientAuthEndpoint::register_account ||
           endpoint == ClientAuthEndpoint::refresh_token || endpoint == ClientAuthEndpoint::update_device ||
           endpoint == ClientAuthEndpoint::delete_device;
}

auto registration_policy(RegistrationPolicy policy) -> RegistrationPolicyDecision
{
    auto result = [&]() -> RegistrationPolicyDecision {
        if (!policy.enabled)
        {
            return {false, "registration disabled"};
        }
        if (policy.require_token && !policy.token_present)
        {
            return {false, "registration token required"};
        }
        return {true, {}};
    }();
    if (result.allowed)
    {
        log_diagnostic("registration_policy.allowed", {
                                                          {"reason", result.reason, false}
        });
    }
    else
    {
        // Audit-routing: a denied registration is one of the five
        // high-signal failure events from the 0.5.0 design doc. We log
        // the structured diagnostic AND write a row to audit_log via
        // the homeserver-installed sink so operators can query
        // `GET /_merovingian/admin/audit?category=policy` to see the
        // configured policy denying the request.
        observability::log_diagnostic_audit("auth", "registration_policy.denied",
                                            {
                                                {"reason", result.reason, false}
        },
                                            observability::LogEventSeverity::warning,
                                            observability::AuditSinkFields{observability::AuditCategory::policy,
                                                                           "registration_policy.denied", "system",
                                                                           "system", result.reason});
    }
    return result;
}

auto session_is_active(SessionRecord const& session, std::chrono::system_clock::time_point now)
    -> SessionInvalidationDecision
{
    auto result = [&]() -> SessionInvalidationDecision {
        if (!user_id_is_valid(session.user_id))
        {
            return {false, "invalid user_id"};
        }
        if (!device_id_is_valid(session.device_id))
        {
            return {false, "invalid device_id"};
        }
        if (session.access_token.user_id != session.user_id || session.access_token.device_id != session.device_id)
        {
            return {false, "token subject mismatch"};
        }
        if (session.device_deleted)
        {
            return {false, "device deleted"};
        }
        if (session.global_logout_generation_revoked)
        {
            return {false, "global logout"};
        }
        auto const token_decision = token_is_active(session.access_token, now);
        if (!token_decision.accepted)
        {
            return {false, token_decision.reason};
        }
        return {true, {}};
    }();
    log_diagnostic(result.active ? "session.active" : "session.invalidated",
                   {
                       {"user_id",   session.user_id,   false},
                       {"device_id", session.device_id, false},
                       {"reason",    result.reason,     false}
    });
    return result;
}

auto make_client_auth_audit_event(ClientAuthEndpoint endpoint, std::string_view user_id, std::string_view device_id,
                                  bool allowed, std::string_view reason) -> ClientAuthAuditEvent
{
    return {
        std::string{"client_auth."} + client_auth_endpoint_name(endpoint),
        std::string{user_id},
        std::string{device_id},
        allowed ? "allowed" : "denied",
        std::string{reason},
    };
}

auto client_auth_audit_summary(ClientAuthAuditEvent const& event) -> std::string
{
    auto summary = "audit event=" + event.event_type + " outcome=" + event.outcome;
    if (!event.user_id.empty())
    {
        summary += " user_id=" + event.user_id;
    }
    if (!event.device_id.empty())
    {
        summary += " device_id=" + event.device_id;
    }
    if (!event.reason.empty())
    {
        summary += " reason=" + event.reason;
    }
    return summary;
}

} // namespace merovingian::auth
