// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/observability/observability.hpp"
#include "merovingian/platform/hardening_self_check.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

SCENARIO("Integrated observability flow emits safe admin audit health and metrics summaries", "[observability][integration]")
{
    GIVEN("an admin action, audit event, structured log, metrics, health, and hardening checks")
    {
        auto const admin_route = merovingian::observability::match_admin_route("POST", "/_merovingian/admin/accounts/@alice:example.org");
        auto const audit = merovingian::observability::make_audit_event(
            merovingian::observability::AuditCategory::admin,
            "admin.account_action",
            "@admin:example.org",
            "@alice:example.org",
            "manual_review",
            "req-42"
        );
        auto log_event = merovingian::observability::StructuredLogEvent{};
        log_event.logger = "admin";
        log_event.level = "info";
        log_event.fields = {
            {"request_id", "req-42", false},
            {"refresh_token", "super-secret", true},
        };
        auto health = merovingian::observability::HealthCheckSnapshot{};
        health.components = {{"admin", merovingian::observability::HealthStatus::ok, "ready"}};
        auto metrics = std::vector<merovingian::observability::MetricSample>{{"admin_requests_total", 1, true}};
        auto const hardening = merovingian::platform::HardeningSelfCheck{
            {{"seccomp", merovingian::platform::HardeningStatus::unknown}},
        };

        WHEN("observability outputs are produced")
        {
            auto const audit_summary = merovingian::observability::audit_event_summary(audit);
            auto const log_summary = merovingian::observability::structured_log_summary(log_event);
            auto const snapshot = merovingian::observability::make_observability_snapshot(health, metrics, hardening);

            THEN("admin routing, audit, logs, metrics, health, and hardening summaries remain safe")
            {
                REQUIRE(admin_route.matched);
                REQUIRE(admin_route.route.operation == merovingian::observability::AdminOperation::account_action);
                REQUIRE(audit.append_only);
                REQUIRE(audit_summary.find("manual_review") != std::string::npos);
                REQUIRE(log_summary.find("super-secret") == std::string::npos);
                REQUIRE(log_summary.find("<redacted>") != std::string::npos);
                REQUIRE(snapshot.hardening_summaries.size() == 1U);
                REQUIRE(merovingian::observability::observability_snapshot_is_safe(snapshot));
            }
        }
    }
}

SCENARIO("Integrated observability flow marks degraded health and rejects unsafe metrics", "[observability][integration]")
{
    GIVEN("a degraded component and unsafe metric")
    {
        auto health = merovingian::observability::HealthCheckSnapshot{};
        health.components = {
            {"database", merovingian::observability::HealthStatus::ok, "reachable"},
            {"policy", merovingian::observability::HealthStatus::degraded, "backoff"},
        };
        auto metrics = std::vector<merovingian::observability::MetricSample>{
            {"events_total", 10, true},
            {"event_content_debug", 1, false},
        };
        auto const hardening = merovingian::platform::HardeningSelfCheck{};

        WHEN("an observability snapshot is produced")
        {
            auto const snapshot = merovingian::observability::make_observability_snapshot(health, metrics, hardening);

            THEN("health status reflects the worst component and unsafe metrics are rejected")
            {
                REQUIRE(snapshot.health.status == merovingian::observability::HealthStatus::degraded);
                REQUIRE_FALSE(merovingian::observability::observability_snapshot_is_safe(snapshot));
            }
        }
    }
}
