// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/trust_safety/PolicyAction.hpp"
#include "merovingian/trust_safety/PolicyDecision.hpp"
#include "merovingian/trust_safety/PolicySurface.hpp"
#include "merovingian/trust_safety/ReviewRecord.hpp"
#include "merovingian/trust_safety/ReviewTarget.hpp"
#include "merovingian/trust_safety/SafetyReportRequest.hpp"
#include "merovingian/trust_safety/PolicyEngine.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

SCENARIO("Integrated trust and safety flow records reports and audits an account restriction",
         "[trust-safety][integration]")
{
    GIVEN("a lock decision for an account and a valid report")
    {
        auto account_decision = merovingian::trust_safety::PolicyDecision{};
        account_decision.allowed = false;
        account_decision.surface = merovingian::trust_safety::PolicySurface::account;
        account_decision.action = merovingian::trust_safety::PolicyAction::lock_account;
        account_decision.reason = merovingian::trust_safety::enforcement_reason("account_review", "account restricted",
                                                                                "account locked by admin review");

        auto report = merovingian::trust_safety::SafetyReportRequest{};
        report.reporter_user_id = "@bob:example.org";
        report.room_id = "!room:example.org";
        report.event_id = "$event";
        report.reason = "policy violation";
        report.score = 25;

        WHEN("the report is validated and the restriction is audited")
        {
            auto const report_decision = merovingian::trust_safety::validate_safety_report(report);
            auto const audit = merovingian::trust_safety::make_safety_audit_event(
                "@bob:example.org", "@alice:example.org", account_decision);

            THEN("reporting stays available and the audit event names the restriction")
            {
                REQUIRE(report_decision.allowed);
                REQUIRE(report_decision.action == merovingian::trust_safety::PolicyAction::accept_report);
                REQUIRE(audit.event_type == "trust_safety.account.lock_account");
            }
        }
    }
}

SCENARIO("Integrated trust and safety flow holds federation, media, and room targets for review",
         "[trust-safety][integration]")
{
    GIVEN("active review records for federation, media, and room targets")
    {
        auto const reason = merovingian::trust_safety::enforcement_reason("manual_review", "target held for review",
                                                                          "administrator requested review");
        auto federation = merovingian::trust_safety::ReviewRecord{};
        federation.target = merovingian::trust_safety::ReviewTarget::federation_server;
        federation.target_id = "matrix.example.org";
        federation.active = true;
        federation.reason = reason;
        auto media = merovingian::trust_safety::ReviewRecord{};
        media.target = merovingian::trust_safety::ReviewTarget::media;
        media.target_id = "media123";
        media.active = true;
        media.reason = reason;
        auto room = merovingian::trust_safety::ReviewRecord{};
        room.target = merovingian::trust_safety::ReviewTarget::room;
        room.target_id = "!room:example.org";
        room.active = true;
        room.reason = reason;

        WHEN("review policy decisions are evaluated")
        {
            auto const federation_decision = merovingian::trust_safety::review_policy(federation);
            auto const media_decision = merovingian::trust_safety::review_policy(media);
            auto const room_decision = merovingian::trust_safety::review_policy(room);

            THEN("each target is held with a fail-closed quarantine action")
            {
                REQUIRE_FALSE(federation_decision.allowed);
                REQUIRE(federation_decision.surface == merovingian::trust_safety::PolicySurface::federation);
                REQUIRE(federation_decision.action == merovingian::trust_safety::PolicyAction::quarantine);
                REQUIRE_FALSE(media_decision.allowed);
                REQUIRE(media_decision.surface == merovingian::trust_safety::PolicySurface::media);
                REQUIRE(media_decision.action == merovingian::trust_safety::PolicyAction::quarantine);
                REQUIRE_FALSE(room_decision.allowed);
                REQUIRE(room_decision.surface == merovingian::trust_safety::PolicySurface::room);
                REQUIRE(room_decision.action == merovingian::trust_safety::PolicyAction::quarantine);
            }
        }
    }
}
