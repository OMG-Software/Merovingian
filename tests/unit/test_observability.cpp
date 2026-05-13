// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/database/statement.hpp"
#include "merovingian/observability/observability.hpp"
#include "merovingian/platform/hardening_self_check.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

SCENARIO("Admin control surfaces default to local-only safe exposure", "[observability][admin]")
{
    GIVEN("admin control surface configurations")
    {
        auto disabled = merovingian::observability::AdminControlSurface{};
        disabled.enabled = false;
        auto socket = merovingian::observability::AdminControlSurface{};
        socket.enabled = true;
        socket.bind_address = "/run/merovingian/admin.sock";
        auto loopback = merovingian::observability::AdminControlSurface{};
        loopback.surface = merovingian::observability::AdminSurface::loopback_http;
        loopback.enabled = true;
        loopback.bind_address = "127.0.0.1";
        auto public_http = loopback;
        public_http.bind_address = "0.0.0.0";

        WHEN("safety is evaluated")
        {
            THEN("disabled, local socket, and loopback surfaces are safe, while public HTTP is not")
            {
                REQUIRE(merovingian::observability::admin_surface_is_safe(disabled));
                REQUIRE(merovingian::observability::admin_surface_is_safe(socket));
                REQUIRE(merovingian::observability::admin_surface_is_safe(loopback));
                REQUIRE_FALSE(merovingian::observability::admin_surface_is_safe(public_http));
            }
        }
    }
}

SCENARIO("Admin routes expose health, metrics, audit, account, review, and shutdown operations",
         "[observability][admin]")
{
    GIVEN("admin route targets")
    {
        WHEN("routes are matched")
        {
            auto const health = merovingian::observability::match_admin_route("GET", "/_merovingian/admin/health");
            auto const metrics = merovingian::observability::match_admin_route("GET", "/_merovingian/admin/metrics");
            auto const audit = merovingian::observability::match_admin_route("GET", "/_merovingian/admin/audit");
            auto const account = merovingian::observability::match_admin_route(
                "POST", "/_merovingian/admin/accounts/@alice:example.org");
            auto const review =
                merovingian::observability::match_admin_route("POST", "/_merovingian/admin/review/media/media123");
            auto const shutdown = merovingian::observability::match_admin_route("POST", "/_merovingian/admin/shutdown");
            auto const incomplete_review =
                merovingian::observability::match_admin_route("POST", "/_merovingian/admin/review/media");

            THEN("valid admin routes match and malformed dynamic routes fail closed")
            {
                REQUIRE(health.matched);
                REQUIRE(health.route.operation == merovingian::observability::AdminOperation::health);
                REQUIRE(metrics.matched);
                REQUIRE(audit.matched);
                REQUIRE(account.matched);
                REQUIRE(review.matched);
                REQUIRE(shutdown.matched);
                REQUIRE_FALSE(incomplete_review.matched);
            }
        }
    }
}

SCENARIO("Append-only audit log event model covers required audit categories", "[observability][audit]")
{
    GIVEN("audit events")
    {
        auto const auth_event = merovingian::observability::make_audit_event(
            merovingian::observability::AuditCategory::auth, "login.denied", "@alice:example.org", "@alice:example.org",
            "bad_credentials", "req-1");
        auto const key_event = merovingian::observability::make_audit_event(
            merovingian::observability::AuditCategory::key_lifecycle, "keys.uploaded", "@alice:example.org", "DEVICE",
            "ok", "req-2");
        auto const policy_event = merovingian::observability::make_audit_event(
            merovingian::observability::AuditCategory::policy, "policy.denied", "@admin:example.org", "media123",
            "media_blocked", "req-3");
        auto const moderation_event = merovingian::observability::make_audit_event(
            merovingian::observability::AuditCategory::moderation, "review.held", "@admin:example.org",
            "!room:example.org", "manual_review", "req-4");
        auto const admin_event = merovingian::observability::make_audit_event(
            merovingian::observability::AuditCategory::admin, "admin.shutdown_requested", "@admin:example.org",
            "server", "operator_request", "req-5");

        WHEN("audit statements are produced")
        {
            auto const statement = merovingian::observability::audit_log_insert_statement(auth_event);
            auto const summary = merovingian::observability::audit_event_summary(policy_event);

            THEN("events are append-only and persistence uses prepared statements")
            {
                REQUIRE(auth_event.append_only);
                REQUIRE(key_event.append_only);
                REQUIRE(policy_event.append_only);
                REQUIRE(moderation_event.append_only);
                REQUIRE(admin_event.append_only);
                REQUIRE(statement.name == "observability_append_audit_event");
                REQUIRE(merovingian::database::prepared_statement_is_valid(statement).valid);
                REQUIRE(summary.find("policy") != std::string::npos);
                REQUIRE(summary.find("media_blocked") != std::string::npos);
            }
        }
    }
}

SCENARIO("Structured log summaries redact sensitive values and document boundaries", "[observability][logging]")
{
    GIVEN("structured log fields")
    {
        auto event = merovingian::observability::StructuredLogEvent{};
        event.logger = "auth";
        event.level = "info";
        event.fields = {
            {"request_id",    "req-1",          false},
            {"access_token",  "secret-token",   true },
            {"event_content", "plaintext body", true },
        };

        WHEN("a log summary is rendered")
        {
            auto const summary = merovingian::observability::structured_log_summary(event);
            auto const notes = merovingian::observability::logging_boundary_notes();

            THEN("sensitive values are redacted and boundaries are documented")
            {
                REQUIRE(summary.find("req-1") != std::string::npos);
                REQUIRE(summary.find("secret-token") == std::string::npos);
                REQUIRE(summary.find("plaintext body") == std::string::npos);
                REQUIRE(summary.find("<redacted>") != std::string::npos);
                REQUIRE(notes.size() == 3U);
                REQUIRE(notes[1].find("access tokens") != std::string::npos);
                REQUIRE(notes[1].find("event content") != std::string::npos);
            }
        }
    }
}

SCENARIO("Metrics and health-check summaries avoid secrets and event contents", "[observability][metrics][health]")
{
    GIVEN("safe metrics and health components")
    {
        auto metrics = std::vector<merovingian::observability::MetricSample>{
            {"http_requests_total",         10, true},
            {"audit_events_appended_total", 2,  true},
        };
        auto unsafe_metrics = metrics;
        unsafe_metrics.push_back({"access_token_value", 1, false});
        auto health = merovingian::observability::HealthCheckSnapshot{};
        health.components = {
            {"database",   merovingian::observability::HealthStatus::ok,       "reachable"     },
            {"federation", merovingian::observability::HealthStatus::degraded, "backoff active"},
        };

        WHEN("metrics and health summaries are evaluated")
        {
            auto const health_summary = merovingian::observability::health_snapshot_summary(health);

            THEN("safe metrics pass and health summaries contain component status only")
            {
                REQUIRE(merovingian::observability::metrics_are_safe(metrics));
                REQUIRE_FALSE(merovingian::observability::metrics_are_safe(unsafe_metrics));
                REQUIRE(health_summary.find("database:ok") != std::string::npos);
                REQUIRE(health_summary.find("federation:degraded") != std::string::npos);
            }
        }
    }
}

SCENARIO("Startup hardening self-check output is represented in observability snapshots", "[observability][hardening]")
{
    GIVEN("hardening self-check output and health metrics")
    {
        auto const hardening = merovingian::platform::HardeningSelfCheck{
            {
             {"stack-protector", merovingian::platform::HardeningStatus::enabled},
             {"relro", merovingian::platform::HardeningStatus::disabled},
             },
        };
        auto health = merovingian::observability::HealthCheckSnapshot{};
        health.components = {
            {"runtime", merovingian::observability::HealthStatus::ok, "started"}
        };
        auto metrics = std::vector<merovingian::observability::MetricSample>{
            {"process_start_time_seconds", 1, true}
        };

        WHEN("an observability snapshot is created")
        {
            auto const snapshot = merovingian::observability::make_observability_snapshot(health, metrics, hardening);
            auto const hardening_summaries = merovingian::observability::hardening_observability_summary(hardening);

            THEN("hardening status is included without unsafe payloads")
            {
                REQUIRE(snapshot.health.status == merovingian::observability::HealthStatus::ok);
                REQUIRE(snapshot.hardening_summaries.size() == 2U);
                REQUIRE(hardening_summaries[0] == "hardening stack-protector=enabled");
                REQUIRE(hardening_summaries[1] == "hardening relro=disabled");
                REQUIRE(merovingian::observability::observability_snapshot_is_safe(snapshot));
            }
        }
    }
}
