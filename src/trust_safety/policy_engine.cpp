// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/trust_safety/policy_engine.hpp"

#include <string>
#include <utility>
#include <vector>

namespace merovingian::trust_safety
{
namespace
{

    [[nodiscard]] auto starts_with(std::string_view value, std::string_view prefix) noexcept -> bool
    {
        return value.size() >= prefix.size() && value.substr(0U, prefix.size()) == prefix;
    }

    [[nodiscard]] auto public_value(std::string_view value) -> database::BoundValue
    {
        return {std::string{value}, false};
    }

    [[nodiscard]] auto reason_or_default(EnforcementReason reason, std::string_view code, std::string_view summary)
        -> EnforcementReason
    {
        if (!reason.code.empty())
        {
            return reason;
        }

        return enforcement_reason(code, summary, summary);
    }

    [[nodiscard]] auto allow(PolicySurface surface) -> PolicyDecision
    {
        return {true, surface, PolicyAction::allow, {}, false, {}};
    }

    [[nodiscard]] auto deny(PolicySurface surface, EnforcementReason reason, PolicyAction action = PolicyAction::deny)
        -> PolicyDecision
    {
        return {false, surface, action, std::move(reason), true, {}};
    }

    [[nodiscard]] auto review(PolicySurface surface, EnforcementReason reason) -> PolicyDecision
    {
        return {false, surface, PolicyAction::quarantine, std::move(reason), true, {}};
    }

    [[nodiscard]] auto route(std::string method, std::string path_template, bool requires_admin) -> ReportingApiRoute
    {
        return {
            std::move(method), std::move(path_template), true, requires_admin, {20U, 60U}
        };
    }

    [[nodiscard]] auto matrix_id_is_valid(std::string_view id) noexcept -> bool
    {
        return id.size() >= 3U && id.front() == '@' && id.find(':') != std::string_view::npos;
    }

    [[nodiscard]] auto non_empty_identifier(std::string_view id) noexcept -> bool
    {
        return !id.empty() && id.find("..") == std::string_view::npos;
    }

    [[nodiscard]] auto has_exactly_two_path_segments(std::string_view suffix) noexcept -> bool
    {
        auto const separator = suffix.find('/');
        return separator != std::string_view::npos && separator > 0U && separator + 1U < suffix.size() &&
               suffix.find('/', separator + 1U) == std::string_view::npos;
    }

    [[nodiscard]] auto matches_report_route(std::string_view target) noexcept -> bool
    {
        auto constexpr prefix = std::string_view{"/_matrix/client/v3/rooms/"};
        auto constexpr report_separator = std::string_view{"/report/"};

        if (!starts_with(target, prefix))
        {
            return false;
        }

        auto const suffix = target.substr(prefix.size());
        auto const report_position = suffix.find(report_separator);
        if (report_position == std::string_view::npos || report_position == 0U)
        {
            return false;
        }

        auto const event_id = suffix.substr(report_position + report_separator.size());
        return !event_id.empty() && event_id.find('/') == std::string_view::npos;
    }

    [[nodiscard]] auto matches_admin_review_route(std::string_view target) noexcept -> bool
    {
        auto constexpr prefix = std::string_view{"/_matrix/client/v3/admin/safety/review/"};

        if (!starts_with(target, prefix))
        {
            return false;
        }

        return has_exactly_two_path_segments(target.substr(prefix.size()));
    }

} // namespace

auto policy_surface_name(PolicySurface surface) noexcept -> char const*
{
    switch (surface)
    {
    case PolicySurface::invite:
        return "invite";
    case PolicySurface::federation:
        return "federation";
    case PolicySurface::media:
        return "media";
    case PolicySurface::registration:
        return "registration";
    case PolicySurface::room:
        return "room";
    case PolicySurface::account:
        return "account";
    }

    return "unknown";
}

auto policy_action_name(PolicyAction action) noexcept -> char const*
{
    switch (action)
    {
    case PolicyAction::allow:
        return "allow";
    case PolicyAction::deny:
        return "deny";
    case PolicyAction::quarantine:
        return "quarantine";
    case PolicyAction::lock_account:
        return "lock_account";
    case PolicyAction::suspend_account:
        return "suspend_account";
    case PolicyAction::accept_report:
        return "accept_report";
    }

    return "unknown";
}

auto review_target_name(ReviewTarget target) noexcept -> char const*
{
    switch (target)
    {
    case ReviewTarget::federation_server:
        return "federation_server";
    case ReviewTarget::media:
        return "media";
    case ReviewTarget::room:
        return "room";
    }

    return "unknown";
}

auto enforcement_reason(std::string_view code, std::string_view public_summary, std::string_view admin_detail)
    -> EnforcementReason
{
    return {std::string{code}, std::string{public_summary}, std::string{admin_detail}, true};
}

auto policy_server_hook_allows(PolicyServerHook const& hook) -> PolicyDecision
{
    if (!hook.enabled)
    {
        return allow(PolicySurface::account);
    }
    if (hook.timeout_milliseconds == 0U)
    {
        return deny(PolicySurface::account,
                    enforcement_reason("policy_server_timeout_unconfigured", "policy check unavailable",
                                       "policy server timeout is zero"));
    }
    if (!hook.reachable && !hook.allow_without_result)
    {
        return deny(PolicySurface::account, enforcement_reason("policy_server_unreachable", "policy check unavailable",
                                                               "policy server was unreachable"));
    }
    if (hook.rule_id.empty() && !hook.allow_without_result)
    {
        return deny(PolicySurface::account, enforcement_reason("policy_server_no_result", "policy check unavailable",
                                                               "policy server returned no rule id"));
    }

    auto decision = allow(PolicySurface::account);
    decision.policy_server_rule_id = hook.rule_id;
    return decision;
}

auto evaluate_invite_policy(InvitePolicyRequest const& request) -> PolicyDecision
{
    if (!matrix_id_is_valid(request.sender_user_id) || !matrix_id_is_valid(request.target_user_id) ||
        request.room_id.empty())
    {
        return deny(PolicySurface::invite,
                    enforcement_reason("invalid_invite_policy_input", "invite cannot be processed",
                                       "invite policy input is incomplete"));
    }
    if (request.blocked_by_local_policy)
    {
        return deny(PolicySurface::invite, enforcement_reason("invite_blocked", "invite blocked by server policy",
                                                              "local invite policy blocked the request"));
    }

    auto external = policy_server_hook_allows(request.policy_server);
    if (!external.allowed)
    {
        external.surface = PolicySurface::invite;
        return external;
    }

    auto decision = allow(PolicySurface::invite);
    decision.policy_server_rule_id = external.policy_server_rule_id;
    return decision;
}

auto evaluate_registration_policy(RegistrationPolicyRequest const& request) -> PolicyDecision
{
    if (!matrix_id_is_valid(request.requested_user_id) || request.requester_address.empty())
    {
        return deny(PolicySurface::registration,
                    enforcement_reason("invalid_registration_policy_input", "registration cannot be processed",
                                       "registration policy input is incomplete"));
    }
    if (!request.registrations_enabled)
    {
        return deny(PolicySurface::registration, enforcement_reason("registration_disabled", "registration is disabled",
                                                                    "local registration policy is disabled"));
    }
    if (request.blocked_by_local_policy)
    {
        return deny(PolicySurface::registration,
                    enforcement_reason("registration_blocked", "registration blocked by server policy",
                                       "local registration policy blocked the request"));
    }

    auto external = policy_server_hook_allows(request.policy_server);
    if (!external.allowed)
    {
        external.surface = PolicySurface::registration;
        return external;
    }

    auto decision = allow(PolicySurface::registration);
    decision.policy_server_rule_id = external.policy_server_rule_id;
    return decision;
}

auto evaluate_account_policy(AccountPolicyRequest const& request) -> PolicyDecision
{
    if (!matrix_id_is_valid(request.user_id))
    {
        return deny(PolicySurface::account,
                    enforcement_reason("invalid_account_policy_input", "account cannot be processed",
                                       "account policy input is incomplete"));
    }
    if (request.enforcement.suspended)
    {
        return deny(PolicySurface::account,
                    reason_or_default(request.enforcement.reason, "account_suspended", "account is suspended"),
                    PolicyAction::suspend_account);
    }
    if (request.enforcement.locked)
    {
        return deny(PolicySurface::account,
                    reason_or_default(request.enforcement.reason, "account_locked", "account is locked"),
                    PolicyAction::lock_account);
    }

    return allow(PolicySurface::account);
}

auto evaluate_federation_policy(FederationPolicyRequest const& request) -> PolicyDecision
{
    if (request.origin_server.empty())
    {
        return deny(PolicySurface::federation,
                    enforcement_reason("invalid_federation_policy_input", "federation request cannot be processed",
                                       "federation policy input is incomplete"));
    }
    if (request.held_for_review)
    {
        return review(PolicySurface::federation,
                      enforcement_reason("federation_held_for_review", "federation request held for review",
                                         "federation origin is held for review"));
    }
    if (request.blocked_by_local_policy)
    {
        return deny(PolicySurface::federation,
                    enforcement_reason("federation_blocked", "federation blocked by server policy",
                                       "local federation policy blocked the origin"));
    }

    auto external = policy_server_hook_allows(request.policy_server);
    if (!external.allowed)
    {
        external.surface = PolicySurface::federation;
        return external;
    }

    auto decision = allow(PolicySurface::federation);
    decision.policy_server_rule_id = external.policy_server_rule_id;
    return decision;
}

auto evaluate_media_policy(MediaPolicyRequest const& request) -> PolicyDecision
{
    if (!non_empty_identifier(request.media_id))
    {
        return deny(PolicySurface::media, enforcement_reason("invalid_media_policy_input", "media cannot be processed",
                                                             "media policy input is incomplete"));
    }
    if (request.held_for_review)
    {
        return review(PolicySurface::media, enforcement_reason("media_held_for_review", "media held for review",
                                                               "media item is held for review"));
    }
    if (request.blocked_by_local_policy)
    {
        return deny(PolicySurface::media, enforcement_reason("media_blocked", "media blocked by server policy",
                                                             "local media policy blocked the item"));
    }

    auto external = policy_server_hook_allows(request.policy_server);
    if (!external.allowed)
    {
        external.surface = PolicySurface::media;
        return external;
    }

    auto decision = allow(PolicySurface::media);
    decision.policy_server_rule_id = external.policy_server_rule_id;
    return decision;
}

auto evaluate_room_policy(RoomPolicyRequest const& request) -> PolicyDecision
{
    if (request.room_id.empty())
    {
        return deny(PolicySurface::room, enforcement_reason("invalid_room_policy_input", "room cannot be processed",
                                                            "room policy input is incomplete"));
    }
    if (request.held_for_review)
    {
        return review(PolicySurface::room,
                      enforcement_reason("room_held_for_review", "room held for review", "room is held for review"));
    }
    if (request.blocked_by_local_policy)
    {
        return deny(PolicySurface::room, enforcement_reason("room_blocked", "room blocked by server policy",
                                                            "local room policy blocked the room"));
    }

    auto external = policy_server_hook_allows(request.policy_server);
    if (!external.allowed)
    {
        external.surface = PolicySurface::room;
        return external;
    }

    auto decision = allow(PolicySurface::room);
    decision.policy_server_rule_id = external.policy_server_rule_id;
    return decision;
}

auto account_enforcement_statements(AccountEnforcementRecord const& record) -> std::vector<database::PreparedStatement>
{
    if (!matrix_id_is_valid(record.user_id))
    {
        return {};
    }

    return {
        {
         "trust_safety_update_account_enforcement", "UPDATE accounts SET suspended = $1, locked = $2, enforcement_reason = $3 WHERE user_id = $4",
         {
                public_value(record.suspended ? "true" : "false"),
                public_value(record.locked ? "true" : "false"),
                public_value(record.reason.code),
                public_value(record.user_id),
            }, },
    };
}

auto review_policy(ReviewRecord const& record) -> PolicyDecision
{
    auto const surface = record.target == ReviewTarget::federation_server ? PolicySurface::federation
                         : record.target == ReviewTarget::media           ? PolicySurface::media
                                                                          : PolicySurface::room;
    if (!non_empty_identifier(record.target_id))
    {
        return deny(surface, enforcement_reason("invalid_review_target", "target cannot be processed",
                                                "review target is invalid"));
    }
    if (!record.active)
    {
        return allow(surface);
    }

    return review(surface, reason_or_default(record.reason, "target_held_for_review", "target held for review"));
}

auto reporting_api_routes() -> std::vector<ReportingApiRoute>
{
    return {
        route("POST", "/_matrix/client/v3/rooms/{roomId}/report/{eventId}", false),
        route("GET", "/_matrix/client/v3/admin/safety/reports", true),
        route("POST", "/_matrix/client/v3/admin/safety/review/{targetType}/{targetId}", true),
    };
}

auto match_reporting_api_route(std::string_view method, std::string_view target) -> ReportingApiRouteMatch
{
    for (auto const& candidate : reporting_api_routes())
    {
        if (candidate.method != method)
        {
            continue;
        }
        if (candidate.path_template == target)
        {
            return {true, candidate, {}};
        }
        if (candidate.path_template == "/_matrix/client/v3/rooms/{roomId}/report/{eventId}" &&
            matches_report_route(target))
        {
            return {true, candidate, {}};
        }
        if (candidate.path_template == "/_matrix/client/v3/admin/safety/review/{targetType}/{targetId}" &&
            matches_admin_review_route(target))
        {
            return {true, candidate, {}};
        }
    }

    return {false, {}, "reporting API route not found"};
}

auto validate_safety_report(SafetyReportRequest const& request) -> PolicyDecision
{
    if (!matrix_id_is_valid(request.reporter_user_id) || request.room_id.empty() || request.event_id.empty())
    {
        return deny(PolicySurface::room, enforcement_reason("invalid_report", "report cannot be processed",
                                                            "report is missing reporter, room, or event"));
    }
    if (request.reason.empty())
    {
        return deny(PolicySurface::room, enforcement_reason("report_reason_required", "report reason is required",
                                                            "report reason is empty"));
    }
    if (request.score < -100 || request.score > 100)
    {
        return deny(PolicySurface::room, enforcement_reason("report_score_out_of_range", "report score is invalid",
                                                            "report score must be between -100 and 100"));
    }

    return {true, PolicySurface::room, PolicyAction::accept_report, {}, false, {}};
}

auto make_safety_audit_event(std::string_view actor, std::string_view entity, PolicyDecision const& decision)
    -> SafetyAuditEvent
{
    return {
        std::string{"trust_safety."} + policy_surface_name(decision.surface) + '.' +
            policy_action_name(decision.action),
        std::string{actor},
        std::string{entity},
        decision.surface,
        decision.action,
        decision.reason,
    };
}

auto safety_audit_summary(SafetyAuditEvent const& event) -> std::string
{
    return event.event_type + " actor=" + event.actor + " entity=" + event.entity + " reason=" + event.reason.code;
}

} // namespace merovingian::trust_safety
