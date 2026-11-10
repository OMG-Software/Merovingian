// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/auth/Session.hpp"

#include "merovingian/auth/RegistrationPolicy.hpp"
#include "merovingian/auth/RegistrationPolicyDecision.hpp"
#include "merovingian/observability/AuditCategory.hpp"
#include "merovingian/observability/AuditSinkFields.hpp"
#include "merovingian/observability/LogEventSeverity.hpp"
#include "merovingian/observability/SingleLog.hpp"
#include "merovingian/observability/StructuredLogField.hpp"

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

} // namespace merovingian::auth
