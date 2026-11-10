// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/LocalDatabaseScope.hpp"
#include "merovingian/homeserver/LocalServices.hpp"
#include "merovingian/observability/AdminOperation.hpp"
#include "merovingian/observability/AuditCategory.hpp"
#include "merovingian/observability/AuditSinkFields.hpp"
#include "merovingian/observability/HealthCheckSnapshot.hpp"
#include "merovingian/observability/HealthStatus.hpp"
#include "merovingian/observability/LogEventSeverity.hpp"
#include "merovingian/observability/MetricSample.hpp"
#include "merovingian/observability/SingleLog.hpp"
#include "merovingian/observability/StructuredLogEvent.hpp"
#include "merovingian/observability/Observability.hpp"
#include "merovingian/platform/HardeningSelfCheck.hpp"
#include "merovingian/platform/HardeningStatus.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

namespace
{

// Resets the thread_local audit-sink database pointer at the end of each
// scenario leaf, mirroring tests/unit/test_local_database_scope.cpp's
// AuditDatabaseReset. Using an RAII guard (rather than a bare statement at
// the end of GIVEN) matters here because a failing REQUIRE throws in
// Catch2: without the guard, a failed assertion would skip the cleanup and
// leave the thread_local pointing at this scenario's now-out-of-scope
// `database`, dangling for whichever test runs next on this thread.
struct AuditDatabaseReset final
{
    ~AuditDatabaseReset()
    {
        merovingian::homeserver::set_current_audit_database(nullptr);
    }
};

} // namespace

SCENARIO("Integrated observability flow emits safe admin audit health and metrics summaries",
         "[observability][integration]")
{
    GIVEN("an admin action, audit event, structured log, metrics, health, and hardening checks")
    {
        auto const admin_route =
            merovingian::observability::match_admin_route("POST", "/_merovingian/admin/accounts/@alice:example.org");
        auto const audit = merovingian::observability::make_audit_event(
            merovingian::observability::AuditCategory::admin, "admin.account_action", "@admin:example.org",
            "@alice:example.org", "manual_review", "req-42");
        auto log_event = merovingian::observability::StructuredLogEvent{};
        log_event.logger = "admin";
        log_event.level = "info";
        log_event.fields = {
            {"request_id",    "req-42",       false},
            {"refresh_token", "super-secret", true },
        };
        auto health = merovingian::observability::HealthCheckSnapshot{};
        health.components = {
            {"admin", merovingian::observability::HealthStatus::ok, "ready"}
        };
        auto metrics = std::vector<merovingian::observability::MetricSample>{
            {"admin_requests_total", 1, true}
        };
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
                // L-11: `append_only` was removed from AuditLogEvent (nothing
                // enforced it); see test_observability.cpp's audit-category
                // scenario for the INSERT-only assertion that replaced it.
                REQUIRE(audit.category == merovingian::observability::AuditCategory::admin);
                REQUIRE(audit_summary.find("manual_review") != std::string::npos);
                REQUIRE(log_summary.find("super-secret") == std::string::npos);
                REQUIRE(log_summary.find("<redacted>") != std::string::npos);
                REQUIRE(snapshot.hardening_summaries.size() == 1U);
                REQUIRE(merovingian::observability::observability_snapshot_is_safe(snapshot));
            }
        }
    }
}

SCENARIO("Integrated observability flow marks degraded health and rejects unsafe metrics",
         "[observability][integration]")
{
    GIVEN("a degraded component and unsafe metric")
    {
        auto health = merovingian::observability::HealthCheckSnapshot{};
        health.components = {
            {"database", merovingian::observability::HealthStatus::ok,       "reachable"},
            {"policy",   merovingian::observability::HealthStatus::degraded, "backoff"  },
        };
        auto metrics = std::vector<merovingian::observability::MetricSample>{
            {"events_total",        10, true },
            {"event_content_debug", 1,  false},
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

SCENARIO("The audit sink stays fail-closed while its database is unavailable and recovers once it opens",
         "[observability][audit][integration]")
{
    // L-10 (security-audit-report-2026-09.md): the audit sink no-ops
    // (drops the event) while the thread-local LocalDatabase is null or
    // closed. The fix (src/homeserver/LocalServices.cpp's
    // local_audit_sink) adds a warn-once-per-episode diagnostic, but must
    // not change the fail-closed *behaviour*: no audit row is fabricated
    // while the database is unavailable, no crash, and no duplicate row
    // once it becomes available again. This spans homeserver + observability,
    // so it belongs here rather than in a single-module unit test.
    AuditDatabaseReset const reset{};
    GIVEN("a LocalDatabase that starts closed")
    {
        auto database = merovingian::homeserver::LocalDatabase{};
        database.opened = false;
        merovingian::homeserver::install_local_audit_database(&database);

        WHEN("several warning-severity diagnostics fire while the database is closed")
        {
            auto const fields =
                merovingian::observability::AuditSinkFields{merovingian::observability::AuditCategory::auth,
                                                            "test.flow.drop", "@alice:example.org", "target", "reason"};
            for (auto attempt = 0; attempt < 5; ++attempt)
            {
                merovingian::observability::log_diagnostic_audit("observability_flow", "test.flow.drop", {},
                                                                 merovingian::observability::LogEventSeverity::warning,
                                                                 fields);
            }

            THEN("no audit row is recorded while the database stays closed")
            {
                REQUIRE(database.audit_events.empty());
            }
        }

        WHEN("the database opens and a further diagnostic fires")
        {
            database.opened = true;
            auto const fields = merovingian::observability::AuditSinkFields{
                merovingian::observability::AuditCategory::auth, "test.flow.recovered", "@alice:example.org", "target",
                "reason"};
            merovingian::observability::log_diagnostic_audit("observability_flow", "test.flow.recovered", {},
                                                             merovingian::observability::LogEventSeverity::warning,
                                                             fields);

            THEN("the audit row lands once the database is available")
            {
                REQUIRE_FALSE(database.audit_events.empty());
                REQUIRE(database.audit_events.back().event_type == "test.flow.recovered");
            }
        }
    }
}
