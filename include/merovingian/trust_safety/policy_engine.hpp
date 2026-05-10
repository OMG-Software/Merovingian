// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <merovingian/database/statement.hpp>
#include <merovingian/http/rate_limit.hpp>

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::trust_safety
{

enum class PolicySurface
{
    invite,
    federation,
    media,
    registration,
    room,
    account,
};

enum class PolicyAction
{
    allow,
    deny,
    quarantine,
    lock_account,
    suspend_account,
    accept_report,
};

enum class ReviewTarget
{
    federation_server,
    media,
    room,
};

struct EnforcementReason final
{
    std::string code{};
    std::string public_summary{};
    std::string admin_detail{};
    bool admin_visible{true};
};

struct PolicyDecision final
{
    bool allowed{false};
    PolicySurface surface{PolicySurface::account};
    PolicyAction action{PolicyAction::deny};
    EnforcementReason reason{};
    bool fail_closed{true};
    std::string policy_server_rule_id{};
};

struct PolicyServerHook final
{
    bool enabled{false};
    bool reachable{true};
    bool allow_without_result{false};
    std::string rule_id{};
    std::uint32_t timeout_milliseconds{250U};
};

struct AccountEnforcementRecord final
{
    std::string user_id{};
    bool suspended{false};
    bool locked{false};
    EnforcementReason reason{};
};

struct InvitePolicyRequest final
{
    std::string sender_user_id{};
    std::string target_user_id{};
    std::string room_id{};
    bool blocked_by_local_policy{false};
    PolicyServerHook policy_server{};
};

struct RegistrationPolicyRequest final
{
    std::string requested_user_id{};
    std::string requester_address{};
    bool registrations_enabled{false};
    bool blocked_by_local_policy{false};
    PolicyServerHook policy_server{};
};

struct AccountPolicyRequest final
{
    std::string user_id{};
    AccountEnforcementRecord enforcement{};
};

struct FederationPolicyRequest final
{
    std::string origin_server{};
    bool held_for_review{false};
    bool blocked_by_local_policy{false};
    PolicyServerHook policy_server{};
};

struct MediaPolicyRequest final
{
    std::string media_id{};
    bool held_for_review{false};
    bool blocked_by_local_policy{false};
    PolicyServerHook policy_server{};
};

struct RoomPolicyRequest final
{
    std::string room_id{};
    bool held_for_review{false};
    bool blocked_by_local_policy{false};
    PolicyServerHook policy_server{};
};

struct ReviewRecord final
{
    ReviewTarget target{ReviewTarget::media};
    std::string target_id{};
    bool active{false};
    EnforcementReason reason{};
};

struct ReportingApiRoute final
{
    std::string method{};
    std::string path_template{};
    bool requires_access_token{true};
    bool requires_admin{false};
    http::RateLimitPolicy rate_limit{};
};

struct ReportingApiRouteMatch final
{
    bool matched{false};
    ReportingApiRoute route{};
    std::string reason{};
};

struct SafetyReportRequest final
{
    std::string reporter_user_id{};
    std::string room_id{};
    std::string event_id{};
    std::string reason{};
    std::int32_t score{0};
};

struct SafetyAuditEvent final
{
    std::string event_type{};
    std::string actor{};
    std::string entity{};
    PolicySurface surface{PolicySurface::account};
    PolicyAction action{PolicyAction::deny};
    EnforcementReason reason{};
};

[[nodiscard]] auto policy_surface_name(PolicySurface surface) noexcept -> char const*;
[[nodiscard]] auto policy_action_name(PolicyAction action) noexcept -> char const*;
[[nodiscard]] auto review_target_name(ReviewTarget target) noexcept -> char const*;
[[nodiscard]] auto enforcement_reason(
    std::string_view code,
    std::string_view public_summary,
    std::string_view admin_detail
) -> EnforcementReason;
[[nodiscard]] auto policy_server_hook_allows(PolicyServerHook const& hook) -> PolicyDecision;
[[nodiscard]] auto evaluate_invite_policy(InvitePolicyRequest const& request) -> PolicyDecision;
[[nodiscard]] auto evaluate_registration_policy(RegistrationPolicyRequest const& request) -> PolicyDecision;
[[nodiscard]] auto evaluate_account_policy(AccountPolicyRequest const& request) -> PolicyDecision;
[[nodiscard]] auto evaluate_federation_policy(FederationPolicyRequest const& request) -> PolicyDecision;
[[nodiscard]] auto evaluate_media_policy(MediaPolicyRequest const& request) -> PolicyDecision;
[[nodiscard]] auto evaluate_room_policy(RoomPolicyRequest const& request) -> PolicyDecision;
[[nodiscard]] auto account_enforcement_statements(AccountEnforcementRecord const& record)
    -> std::vector<database::PreparedStatement>;
[[nodiscard]] auto review_policy(ReviewRecord const& record) -> PolicyDecision;
[[nodiscard]] auto reporting_api_routes() -> std::vector<ReportingApiRoute>;
[[nodiscard]] auto match_reporting_api_route(std::string_view method, std::string_view target)
    -> ReportingApiRouteMatch;
[[nodiscard]] auto validate_safety_report(SafetyReportRequest const& request) -> PolicyDecision;
[[nodiscard]] auto make_safety_audit_event(
    std::string_view actor,
    std::string_view entity,
    PolicyDecision const& decision
) -> SafetyAuditEvent;
[[nodiscard]] auto safety_audit_summary(SafetyAuditEvent const& event) -> std::string;

} // namespace merovingian::trust_safety
