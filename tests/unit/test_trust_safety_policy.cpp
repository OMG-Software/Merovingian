// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/database/statement.hpp>
#include <merovingian/trust_safety/policy_engine.hpp>

#include <catch2/catch_test_macros.hpp>

#include <string>

SCENARIO("Trust and safety policy engine exposes all policy surfaces", "[trust-safety][policy]")
{
    GIVEN("policy surface and action enums")
    {
        WHEN("names are requested")
        {
            THEN("invite, federation, media, registration, room, and account surfaces exist")
            {
                REQUIRE(std::string{merovingian::trust_safety::policy_surface_name(merovingian::trust_safety::PolicySurface::invite)} == "invite");
                REQUIRE(std::string{merovingian::trust_safety::policy_surface_name(merovingian::trust_safety::PolicySurface::federation)} == "federation");
                REQUIRE(std::string{merovingian::trust_safety::policy_surface_name(merovingian::trust_safety::PolicySurface::media)} == "media");
                REQUIRE(std::string{merovingian::trust_safety::policy_surface_name(merovingian::trust_safety::PolicySurface::registration)} == "registration");
                REQUIRE(std::string{merovingian::trust_safety::policy_surface_name(merovingian::trust_safety::PolicySurface::room)} == "room");
                REQUIRE(std::string{merovingian::trust_safety::policy_surface_name(merovingian::trust_safety::PolicySurface::account)} == "account");
                REQUIRE(std::string{merovingian::trust_safety::policy_action_name(merovingian::trust_safety::PolicyAction::suspend_account)} == "suspend_account");
                REQUIRE(std::string{merovingian::trust_safety::policy_action_name(merovingian::trust_safety::PolicyAction::quarantine)} == "quarantine");
            }
        }
    }
}

SCENARIO("Policy server hooks fail closed when unavailable", "[trust-safety][policy-server]")
{
    GIVEN("policy server hooks")
    {
        auto disabled = merovingian::trust_safety::PolicyServerHook{};
        auto unreachable = merovingian::trust_safety::PolicyServerHook{};
        unreachable.enabled = true;
        unreachable.reachable = false;
        auto unreachable_but_optional = unreachable;
        unreachable_but_optional.allow_without_result = true;

        WHEN("hooks are evaluated")
        {
            auto const disabled_decision = merovingian::trust_safety::policy_server_hook_allows(disabled);
            auto const unreachable_decision = merovingian::trust_safety::policy_server_hook_allows(unreachable);
            auto const optional_decision = merovingian::trust_safety::policy_server_hook_allows(unreachable_but_optional);

            THEN("required hooks fail closed and optional hooks pass")
            {
                REQUIRE(disabled_decision.allowed);
                REQUIRE_FALSE(unreachable_decision.allowed);
                REQUIRE(unreachable_decision.fail_closed);
                REQUIRE(unreachable_decision.reason.code == "policy_server_unreachable");
                REQUIRE(optional_decision.allowed);
            }
        }
    }
}

SCENARIO("Invite and registration policies block local denials and malformed input", "[trust-safety][policy]")
{
    GIVEN("invite and registration requests")
    {
        auto invite = merovingian::trust_safety::InvitePolicyRequest{};
        invite.sender_user_id = "@alice:example.org";
        invite.target_user_id = "@bob:example.org";
        invite.room_id = "!room:example.org";
        auto blocked_invite = invite;
        blocked_invite.blocked_by_local_policy = true;

        auto registration = merovingian::trust_safety::RegistrationPolicyRequest{};
        registration.requested_user_id = "@carol:example.org";
        registration.requester_address = "203.0.113.10";
        registration.registrations_enabled = true;
        auto disabled_registration = registration;
        disabled_registration.registrations_enabled = false;

        WHEN("policy is evaluated")
        {
            auto const invite_allowed = merovingian::trust_safety::evaluate_invite_policy(invite);
            auto const invite_blocked = merovingian::trust_safety::evaluate_invite_policy(blocked_invite);
            auto const registration_allowed = merovingian::trust_safety::evaluate_registration_policy(registration);
            auto const registration_blocked = merovingian::trust_safety::evaluate_registration_policy(disabled_registration);

            THEN("safe inputs pass and blocked inputs fail closed")
            {
                REQUIRE(invite_allowed.allowed);
                REQUIRE_FALSE(invite_blocked.allowed);
                REQUIRE(invite_blocked.reason.code == "invite_blocked");
                REQUIRE(registration_allowed.allowed);
                REQUIRE_FALSE(registration_blocked.allowed);
                REQUIRE(registration_blocked.reason.code == "registration_disabled");
            }
        }
    }
}

SCENARIO("Account suspension and locking integrate with account enforcement records", "[trust-safety][account]")
{
    GIVEN("account enforcement records")
    {
        auto const reason = merovingian::trust_safety::enforcement_reason("manual_review", "account restricted", "admin reviewed account");
        auto suspended = merovingian::trust_safety::AccountEnforcementRecord{};
        suspended.user_id = "@alice:example.org";
        suspended.suspended = true;
        suspended.reason = reason;
        auto locked = suspended;
        locked.suspended = false;
        locked.locked = true;

        WHEN("account policy and statements are generated")
        {
            auto const suspended_decision = merovingian::trust_safety::evaluate_account_policy({"@alice:example.org", suspended});
            auto const locked_decision = merovingian::trust_safety::evaluate_account_policy({"@alice:example.org", locked});
            auto const statements = merovingian::trust_safety::account_enforcement_statements(suspended);

            THEN("account state fails closed and can be persisted through prepared statements")
            {
                REQUIRE_FALSE(suspended_decision.allowed);
                REQUIRE(suspended_decision.action == merovingian::trust_safety::PolicyAction::suspend_account);
                REQUIRE_FALSE(locked_decision.allowed);
                REQUIRE(locked_decision.action == merovingian::trust_safety::PolicyAction::lock_account);
                REQUIRE(statements.size() == 1U);
                REQUIRE(statements.front().name == "trust_safety_update_account_enforcement");
                REQUIRE(merovingian::database::prepared_statement_is_valid(statements.front()).valid);
            }
        }
    }
}

SCENARIO("Federation, media, and room review scaffolds produce quarantine decisions", "[trust-safety][review]")
{
    GIVEN("federation, media, and room policy requests held for review")
    {
        auto federation = merovingian::trust_safety::FederationPolicyRequest{};
        federation.origin_server = "matrix.example.org";
        federation.held_for_review = true;
        auto media = merovingian::trust_safety::MediaPolicyRequest{};
        media.media_id = "media123";
        media.held_for_review = true;
        auto room = merovingian::trust_safety::RoomPolicyRequest{};
        room.room_id = "!room:example.org";
        room.held_for_review = true;

        WHEN("policy is evaluated")
        {
            auto const federation_decision = merovingian::trust_safety::evaluate_federation_policy(federation);
            auto const media_decision = merovingian::trust_safety::evaluate_media_policy(media);
            auto const room_decision = merovingian::trust_safety::evaluate_room_policy(room);

            THEN("all review-held surfaces fail closed with quarantine actions")
            {
                REQUIRE_FALSE(federation_decision.allowed);
                REQUIRE(federation_decision.action == merovingian::trust_safety::PolicyAction::quarantine);
                REQUIRE_FALSE(media_decision.allowed);
                REQUIRE(media_decision.action == merovingian::trust_safety::PolicyAction::quarantine);
                REQUIRE_FALSE(room_decision.allowed);
                REQUIRE(room_decision.action == merovingian::trust_safety::PolicyAction::quarantine);
            }
        }
    }
}

SCENARIO("Reporting API scaffold validates reports and exposes admin routes", "[trust-safety][reports]")
{
    GIVEN("reporting routes and report requests")
    {
        auto valid_report = merovingian::trust_safety::SafetyReportRequest{};
        valid_report.reporter_user_id = "@alice:example.org";
        valid_report.room_id = "!room:example.org";
        valid_report.event_id = "$event";
        valid_report.reason = "spam";
        valid_report.score = 50;
        auto invalid_report = valid_report;
        invalid_report.reason.clear();

        WHEN("routes are matched and reports validated")
        {
            auto const report_route = merovingian::trust_safety::match_reporting_api_route("POST", "/_matrix/client/v3/rooms/!room:example.org/report/$event");
            auto const unrelated_room_route = merovingian::trust_safety::match_reporting_api_route("POST", "/_matrix/client/v3/rooms/!room:example.org/leave");
            auto const malformed_report_route = merovingian::trust_safety::match_reporting_api_route("POST", "/_matrix/client/v3/rooms/!room:example.org/report/");
            auto const nested_report_route = merovingian::trust_safety::match_reporting_api_route("POST", "/_matrix/client/v3/rooms/!room:example.org/report/$event/extra");
            auto const admin_route = merovingian::trust_safety::match_reporting_api_route("GET", "/_matrix/client/v3/admin/safety/reports");
            auto const valid_decision = merovingian::trust_safety::validate_safety_report(valid_report);
            auto const invalid_decision = merovingian::trust_safety::validate_safety_report(invalid_report);

            THEN("client and admin reporting APIs exist and invalid reports fail closed")
            {
                REQUIRE(report_route.matched);
                REQUIRE_FALSE(report_route.route.requires_admin);
                REQUIRE_FALSE(unrelated_room_route.matched);
                REQUIRE_FALSE(malformed_report_route.matched);
                REQUIRE_FALSE(nested_report_route.matched);
                REQUIRE(admin_route.matched);
                REQUIRE(admin_route.route.requires_admin);
                REQUIRE(valid_decision.allowed);
                REQUIRE(valid_decision.action == merovingian::trust_safety::PolicyAction::accept_report);
                REQUIRE_FALSE(invalid_decision.allowed);
                REQUIRE(invalid_decision.reason.code == "report_reason_required");
            }
        }
    }
}

SCENARIO("Admin review route scaffold requires target type and target id path segments", "[trust-safety][reports]")
{
    GIVEN("admin review route targets")
    {
        WHEN("routes are matched")
        {
            auto const valid_route = merovingian::trust_safety::match_reporting_api_route("POST", "/_matrix/client/v3/admin/safety/review/media/media123");
            auto const missing_both = merovingian::trust_safety::match_reporting_api_route("POST", "/_matrix/client/v3/admin/safety/review/");
            auto const missing_id = merovingian::trust_safety::match_reporting_api_route("POST", "/_matrix/client/v3/admin/safety/review/media");
            auto const extra_segment = merovingian::trust_safety::match_reporting_api_route("POST", "/_matrix/client/v3/admin/safety/review/media/media123/extra");

            THEN("only complete admin review routes are matched")
            {
                REQUIRE(valid_route.matched);
                REQUIRE(valid_route.route.requires_admin);
                REQUIRE_FALSE(missing_both.matched);
                REQUIRE_FALSE(missing_id.matched);
                REQUIRE_FALSE(extra_segment.matched);
            }
        }
    }
}

SCENARIO("Safety audit events expose admin-visible enforcement reasons", "[trust-safety][audit]")
{
    GIVEN("a denied media policy decision")
    {
        auto media = merovingian::trust_safety::MediaPolicyRequest{};
        media.media_id = "media123";
        media.blocked_by_local_policy = true;

        WHEN("an audit event is generated")
        {
            auto const decision = merovingian::trust_safety::evaluate_media_policy(media);
            auto const event = merovingian::trust_safety::make_safety_audit_event("@admin:example.org", "media123", decision);
            auto const summary = merovingian::trust_safety::safety_audit_summary(event);

            THEN("the audit event includes surface, action, actor, entity, and reason")
            {
                REQUIRE(event.event_type == "trust_safety.media.deny");
                REQUIRE(event.reason.admin_visible);
                REQUIRE(summary.find("@admin:example.org") != std::string::npos);
                REQUIRE(summary.find("media_blocked") != std::string::npos);
            }
        }
    }
}
