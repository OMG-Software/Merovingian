// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/statement.hpp"
#include "merovingian/trust_safety/EnforcementReason.hpp"
#include "merovingian/trust_safety/FederationPolicyRequest.hpp"
#include "merovingian/trust_safety/MediaPolicyRequest.hpp"
#include "merovingian/trust_safety/PolicyDecision.hpp"
#include "merovingian/trust_safety/PolicyServerHook.hpp"
#include "merovingian/trust_safety/RegistrationPolicyRequest.hpp"
#include "merovingian/trust_safety/ReportingApiRoute.hpp"
#include "merovingian/trust_safety/ReportingApiRouteMatch.hpp"
#include "merovingian/trust_safety/ReviewRecord.hpp"
#include "merovingian/trust_safety/RoomPolicyRequest.hpp"
#include "merovingian/trust_safety/SafetyAuditEvent.hpp"
#include "merovingian/trust_safety/SafetyReportRequest.hpp"
#include "merovingian/trust_safety/UserReportRequest.hpp"
#include "merovingian/trust_safety/policy_enums.hpp"

#include <string>
#include <string_view>
#include <vector>

namespace merovingian::trust_safety
{

[[nodiscard]] auto policy_surface_name(PolicySurface surface) noexcept -> char const*;
[[nodiscard]] auto policy_action_name(PolicyAction action) noexcept -> char const*;
[[nodiscard]] auto review_target_name(ReviewTarget target) noexcept -> char const*;
[[nodiscard]] auto enforcement_reason(std::string_view code, std::string_view public_summary,
                                      std::string_view admin_detail) -> EnforcementReason;
[[nodiscard]] auto policy_server_hook_allows(PolicyServerHook const& hook) -> PolicyDecision;
[[nodiscard]] auto evaluate_registration_policy(RegistrationPolicyRequest const& request) -> PolicyDecision;
[[nodiscard]] auto evaluate_federation_policy(FederationPolicyRequest const& request) -> PolicyDecision;
[[nodiscard]] auto evaluate_media_policy(MediaPolicyRequest const& request) -> PolicyDecision;
[[nodiscard]] auto evaluate_room_policy(RoomPolicyRequest const& request) -> PolicyDecision;
[[nodiscard]] auto review_policy(ReviewRecord const& record) -> PolicyDecision;
[[nodiscard]] auto reporting_api_routes() -> std::vector<ReportingApiRoute>;
[[nodiscard]] auto match_reporting_api_route(std::string_view method, std::string_view target)
    -> ReportingApiRouteMatch;
[[nodiscard]] auto validate_safety_report(SafetyReportRequest const& request) -> PolicyDecision;
[[nodiscard]] auto validate_user_report(UserReportRequest const& request) -> PolicyDecision;
[[nodiscard]] auto make_safety_audit_event(std::string_view actor, std::string_view entity,
                                           PolicyDecision const& decision) -> SafetyAuditEvent;
[[nodiscard]] auto safety_audit_summary(SafetyAuditEvent const& event) -> std::string;

} // namespace merovingian::trust_safety
