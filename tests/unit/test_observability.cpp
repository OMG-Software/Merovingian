// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/database/statement.hpp"
#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"
#include "merovingian/platform/hardening_self_check.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <string>
#include <thread>
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

SCENARIO("Audit log events cover required audit categories and persist only via INSERT", "[observability][audit]")
{
    // L-11 (security-audit-report-2026-09.md): AuditLogEvent used to carry
    // an `append_only` flag that nothing ever consulted -- it was removed
    // rather than enforced, since real enforcement (a database trigger
    // rejecting UPDATE/DELETE) requires a migration outside this change's
    // scope. What this scenario asserts instead is the guarantee that
    // actually exists: the only SQL `audit_log_insert_statement` ever
    // produces is an INSERT, never an UPDATE or DELETE.
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

            THEN("every category round-trips through make_audit_event and persistence is INSERT-only")
            {
                REQUIRE(auth_event.category == merovingian::observability::AuditCategory::auth);
                REQUIRE(key_event.category == merovingian::observability::AuditCategory::key_lifecycle);
                REQUIRE(policy_event.category == merovingian::observability::AuditCategory::policy);
                REQUIRE(moderation_event.category == merovingian::observability::AuditCategory::moderation);
                REQUIRE(admin_event.category == merovingian::observability::AuditCategory::admin);
                REQUIRE(statement.name == "observability_append_audit_event");
                REQUIRE(merovingian::database::prepared_statement_is_valid(statement).valid);
                REQUIRE(statement.sql.find("INSERT") == 0U);
                REQUIRE(statement.sql.find("UPDATE") == std::string::npos);
                REQUIRE(statement.sql.find("DELETE") == std::string::npos);
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
                REQUIRE(notes[0].find("trace identifiers") != std::string::npos);
            }
        }
    }
}

SCENARIO("Correlation contexts produce stable request trace and span fields", "[observability][logging][correlation]")
{
    GIVEN("a generated correlation context")
    {
        auto const correlation = merovingian::observability::make_correlation_context(42U);

        WHEN("correlation fields are attached to a diagnostic event")
        {
            auto fields = merovingian::observability::with_correlation_fields(
                correlation, {
                                 {"method", "GET",                         false},
                                 {"target", "/_merovingian/admin/metrics", false}
            });
            auto const summary = merovingian::observability::diagnostic_log_summary("local_router", "request.received",
                                                                                    std::move(fields));

            THEN("the request id, trace id, and span id are exposed in the log-safe format")
            {
                REQUIRE(correlation.request_id == "req-000000000000002a");
                REQUIRE(correlation.trace_id.size() == 32U);
                REQUIRE(correlation.span_id.size() == 16U);
                REQUIRE(summary.find("request_id=req-000000000000002a") != std::string::npos);
                REQUIRE(summary.find("trace_id=") != std::string::npos);
                REQUIRE(summary.find("span_id=") != std::string::npos);
            }
        }
    }
}

SCENARIO("Low-severity logging flushes after one second or one hundred messages", "[observability][logging]")
{
    using FlushPolicy = merovingian::observability::LowSeverityFlushPolicy;

    GIVEN("a fresh low-severity flush policy")
    {
        auto policy = FlushPolicy{};
        auto const start = FlushPolicy::Clock::time_point{};

        WHEN("the first low-severity message is recorded")
        {
            auto const flush_requested = policy.observe_message(false, start);

            THEN("the message does not flush immediately, but arms a one-second deadline")
            {
                REQUIRE_FALSE(flush_requested);
                REQUIRE(policy.pending_count() == 1U);
                REQUIRE(policy.next_deadline().has_value());
                REQUIRE(*policy.next_deadline() == start + FlushPolicy::time_interval());
                REQUIRE_FALSE(policy.flush_due(start + std::chrono::milliseconds{999}));
                REQUIRE(policy.flush_due(start + FlushPolicy::time_interval()));
            }
        }

        WHEN("one hundred low-severity messages are recorded before the deadline")
        {
            auto flush_requested = false;
            for (auto index = std::size_t{0U}; index < FlushPolicy::message_interval(); ++index)
            {
                flush_requested = policy.observe_message(false, start);
            }

            THEN("the one-hundredth message forces a flush and resets the timer state")
            {
                REQUIRE(flush_requested);
                REQUIRE(policy.pending_count() == 0U);
                REQUIRE_FALSE(policy.next_deadline().has_value());
            }
        }

        WHEN("a high-severity message arrives while low-severity data is pending")
        {
            REQUIRE_FALSE(policy.observe_message(false, start));
            auto const flush_requested = policy.observe_message(true, start + std::chrono::milliseconds{250});

            THEN("the flush happens immediately and clears the pending low-severity state")
            {
                REQUIRE(flush_requested);
                REQUIRE(policy.pending_count() == 0U);
                REQUIRE_FALSE(policy.next_deadline().has_value());
            }
        }
    }
}

SCENARIO("Diagnostic log summaries preserve join context while redacting unsafe fields",
         "[observability][logging][diagnostics]")
{
    GIVEN("a client request diagnostic with a join target and unsafe fields")
    {
        auto const target = merovingian::observability::sanitized_http_target(
            "/_matrix/client/v3/join/!room:example.org?server_name=example.org&access_token=secret-token");
        auto fields = std::vector<merovingian::observability::StructuredLogField>{
            {"method",       "POST",         false},
            {"target",       target,         false},
            {"actor",        "@alice:test",  false},
            {"body",         "raw-json",     false},
            {"body_bytes",   "123",          false},
            {"access_token", "secret-token", false},
            {"status",       "403",          false},
            {"reason",       "unknown room", false},
        };

        WHEN("the diagnostic summary is rendered")
        {
            auto const summary = merovingian::observability::diagnostic_log_summary(
                "client_server", "room.join.rejected", std::move(fields));

            THEN("route, actor, status, and reason survive, but secrets and request bodies do not")
            {
                REQUIRE(summary.find("event=room.join.rejected") != std::string::npos);
                REQUIRE(summary.find("method=POST") != std::string::npos);
                REQUIRE(summary.find("target=/_matrix/client/v3/join/"
                                     "!room:example.org?server_name=example.org&access_token=<redacted>") !=
                        std::string::npos);
                REQUIRE(summary.find("actor=@alice:test") != std::string::npos);
                REQUIRE(summary.find("status=403") != std::string::npos);
                REQUIRE(summary.find("reason=unknown room") != std::string::npos);
                REQUIRE(summary.find("secret-token") == std::string::npos);
                REQUIRE(summary.find("raw-json") == std::string::npos);
                REQUIRE(summary.find("body=<redacted>") != std::string::npos);
                REQUIRE(summary.find("body_bytes=123") != std::string::npos);
            }
        }
    }
}

SCENARIO("Sanitized HTTP targets redact a bare 'token' query parameter", "[observability][logging][security]")
{
    GIVEN("the registration-token validity endpoint's target with the token in the query string")
    {
        // GET /_matrix/client/v1/register/m.login.registration_token/validity?token=<secret>
        // passes the plaintext registration token as a query parameter named
        // exactly "token" (not "access_token" or another already-recognized
        // marker) — every request target is logged via sanitized_http_target.
        auto const target = merovingian::observability::sanitized_http_target(
            "/_matrix/client/v1/register/m.login.registration_token/validity?token=super-secret-registration-token");

        WHEN("the target is rendered for logging")
        {
            THEN("the token value is redacted, not the literal secret")
            {
                REQUIRE(target.find("token=<redacted>") != std::string::npos);
                REQUIRE(target.find("super-secret-registration-token") == std::string::npos);
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

SCENARIO("Prometheus metrics summaries keep stable help type and safe labels", "[observability][metrics]")
{
    GIVEN("documented safe metrics with labels and an unsafe metric")
    {
        auto metrics = std::vector<merovingian::observability::MetricSample>{
            {"merovingian_server_identity",
             1, true,
             merovingian::observability::MetricType::gauge,
             "Identity labels for the running homeserver process.",                                {{"server_name", "example.org", true}}},
            {"audit_events_appended_total",
             2, true,
             merovingian::observability::MetricType::counter,
             "Total number of durable audit events appended since the current store was created.", {}                                    },
            {"access_token_debug_total",
             1, false,
             merovingian::observability::MetricType::counter,
             "Unsafe debug metric that must never be exported.",                                   {}                                    },
        };

        WHEN("the metrics are rendered for scrape/export")
        {
            auto const summary = merovingian::observability::prometheus_metrics_summary(metrics);

            THEN("safe metric families render with HELP TYPE and labels, while unsafe metrics are excluded")
            {
                REQUIRE(summary.find("# HELP merovingian_server_identity Identity labels for the running homeserver "
                                     "process.") != std::string::npos);
                REQUIRE(summary.find("# TYPE merovingian_server_identity gauge") != std::string::npos);
                REQUIRE(summary.find("merovingian_server_identity{server_name=\"example.org\"} 1") !=
                        std::string::npos);
                REQUIRE(summary.find("# TYPE audit_events_appended_total counter") != std::string::npos);
                REQUIRE(summary.find("audit_events_appended_total 2") != std::string::npos);
                REQUIRE(summary.find("access_token_debug_total") == std::string::npos);
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

SCENARIO("redact_log_message redacts key=value tokens carrying secret markers in freeform text",
         "[observability][logging][redaction]")
{
    // M-11 (security-audit-report-2026-09.md): the legacy LOG_*/LOGF_*
    // macros pass a caller-built std::string straight to SingleLog, so they
    // cannot carry a StructuredLogField's `sensitive` bit. redact_log_message
    // is the boundary SingleLog::log() now applies to every line (see
    // logger.hpp) so a plain-string call site cannot bypass redaction the
    // way structured `log_diagnostic` fields already could not.
    GIVEN("a message with no key=value tokens")
    {
        WHEN("it is redacted")
        {
            auto const redacted =
                merovingian::observability::redact_log_message("Federation worker: runtime hardening applied");

            THEN("plain prose passes through unchanged")
            {
                REQUIRE(redacted == "Federation worker: runtime hardening applied");
            }
        }
    }

    GIVEN("a message with a single sensitive key=value token")
    {
        WHEN("it is redacted")
        {
            auto const redacted =
                merovingian::observability::redact_log_message("login attempt access_token=abc123XYZ rejected");

            THEN("the token's value is replaced and the surrounding words survive")
            {
                REQUIRE(redacted == "login attempt access_token=<redacted> rejected");
                REQUIRE(redacted.find("abc123XYZ") == std::string::npos);
            }
        }
    }

    GIVEN("a message with both a sensitive and a non-sensitive key=value token")
    {
        WHEN("it is redacted")
        {
            auto const redacted = merovingian::observability::redact_log_message(
                "Federation worker starting: shard=0 config=/etc/merovingian.toml token=super-secret");

            THEN("only the sensitive token is redacted; file paths and non-secret fields are untouched")
            {
                REQUIRE(redacted.find("shard=0") != std::string::npos);
                REQUIRE(redacted.find("config=/etc/merovingian.toml") != std::string::npos);
                REQUIRE(redacted.find("token=<redacted>") != std::string::npos);
                REQUIRE(redacted.find("super-secret") == std::string::npos);
            }
        }
    }

    GIVEN("a message with a password field")
    {
        WHEN("it is redacted")
        {
            auto const redacted = merovingian::observability::redact_log_message("reset password=hunter2 for user");

            THEN("the password value does not reach the redacted line")
            {
                REQUIRE(redacted.find("password=<redacted>") != std::string::npos);
                REQUIRE(redacted.find("hunter2") == std::string::npos);
            }
        }
    }

    GIVEN("a composed log line whose last token is sensitive, followed by the record terminator")
    {
        WHEN("it is redacted")
        {
            auto const redacted =
                merovingian::observability::redact_log_message("auth:  event=login.rejected password=hunter2\n");

            THEN("the value is redacted and the line still ends the record, so the next record cannot join it")
            {
                REQUIRE(redacted == "auth:  event=login.rejected password=<redacted>\n");
            }
        }
    }
}

SCENARIO("DropEpisodePolicy reports exactly one drop episode per contiguous run of failures",
         "[observability][logging][backpressure]")
{
    // L-13 / L-10 (security-audit-report-2026-09.md): shared by the bounded
    // console/file log queues and the audit-sink no-op path. The behaviour
    // under test -- a flood produces one warning signal, not one per
    // dropped item, and the total dropped count keeps accumulating -- is
    // tested at the policy level (deterministic, no background threads or
    // real queue capacity involved) rather than by racing SingleLog's
    // asynchronous writer threads, which would make the test's outcome
    // depend on machine speed.
    GIVEN("a fresh policy")
    {
        auto policy = merovingian::observability::DropEpisodePolicy{};

        WHEN("no attempts have been observed yet")
        {
            THEN("it starts with nothing dropped and no active episode")
            {
                REQUIRE(policy.dropped_total() == 0U);
                REQUIRE_FALSE(policy.in_drop_episode());
            }
        }

        WHEN("a run of successful attempts is observed")
        {
            REQUIRE_FALSE(policy.observe(true));
            REQUIRE_FALSE(policy.observe(true));

            THEN("nothing is reported as dropped and no episode is entered")
            {
                REQUIRE(policy.dropped_total() == 0U);
                REQUIRE_FALSE(policy.in_drop_episode());
            }
        }

        WHEN("a flood of failed attempts follows a success")
        {
            REQUIRE_FALSE(policy.observe(true));
            auto const first_drop_warns = policy.observe(false);
            auto const second_drop_warns = policy.observe(false);
            auto const third_drop_warns = policy.observe(false);

            THEN("only the first failure in the run signals a warning, but every failure counts")
            {
                REQUIRE(first_drop_warns);
                REQUIRE_FALSE(second_drop_warns);
                REQUIRE_FALSE(third_drop_warns);
                REQUIRE(policy.dropped_total() == 3U);
                REQUIRE(policy.in_drop_episode());
            }
        }

        WHEN("the flood recovers and then floods again")
        {
            REQUIRE(policy.observe(false));
            REQUIRE_FALSE(policy.observe(false));
            REQUIRE_FALSE(policy.observe(true));
            auto const second_episode_warns = policy.observe(false);

            THEN("a success ends the episode, so the next failure warns again")
            {
                REQUIRE(second_episode_warns);
                REQUIRE(policy.dropped_total() == 3U);
                REQUIRE(policy.in_drop_episode());
            }
        }
    }
}

namespace
{

// Test-only audit sink for the L-09 concurrency scenario below. AuditSink is
// a plain function pointer (see logger.hpp), so this must be a free
// function, not a capturing lambda.
std::atomic<std::size_t> g_test_audit_sink_invocations{0U}; // NOLINT

auto counting_test_audit_sink(merovingian::observability::AuditSinkFields const& /*fields*/) -> void
{
    g_test_audit_sink_invocations.fetch_add(1U, std::memory_order_relaxed);
}

} // namespace

SCENARIO("The audit sink survives concurrent installation and invocation without corruption",
         "[observability][audit][thread-safety]")
{
    // L-09 (security-audit-report-2026-09.md): `set_audit_sink()` used to
    // write a plain (non-atomic) function pointer while `log_diagnostic_audit`
    // read it from arbitrary threads. This scenario exercises exactly that
    // pattern -- concurrent installers and concurrent invokers -- so a TSan
    // build (tests/integration/AGENTS.md: sanitizers run in CI) can catch a
    // regression. Per project rule, every thread is joined before any
    // REQUIRE runs: Catch2 assertions are not thread-safe, and a live
    // std::thread next to a failing REQUIRE aborts the whole binary.
    GIVEN("the current audit sink, saved so this scenario can restore it afterwards")
    {
        auto const previous_sink = merovingian::observability::the_audit_sink().load(std::memory_order_acquire);
        g_test_audit_sink_invocations.store(0U, std::memory_order_relaxed);

        WHEN("multiple threads install the sink while multiple other threads invoke it")
        {
            auto threads = std::vector<std::thread>{};
            constexpr auto installer_threads = 4;
            constexpr auto invoker_threads = 4;
            constexpr auto invocations_per_thread = 200;

            for (auto i = 0; i < installer_threads; ++i)
            {
                threads.emplace_back([] {
                    for (auto j = 0; j < 50; ++j)
                    {
                        merovingian::observability::set_audit_sink(&counting_test_audit_sink);
                    }
                });
            }
            for (auto i = 0; i < invoker_threads; ++i)
            {
                threads.emplace_back([] {
                    auto const fields =
                        merovingian::observability::AuditSinkFields{merovingian::observability::AuditCategory::auth,
                                                                    "test.concurrent", "actor", "target", "reason"};
                    for (auto j = 0; j < invocations_per_thread; ++j)
                    {
                        merovingian::observability::log_diagnostic_audit(
                            "test_observability", "test.concurrent", {},
                            merovingian::observability::LogEventSeverity::warning, fields);
                    }
                });
            }

            // Every thread is joined here, before any assertion, per the
            // project's Catch2-threading rule.
            for (auto& worker : threads)
            {
                worker.join();
            }

            THEN("the sink remains a valid, callable pointer afterward with no corruption")
            {
                merovingian::observability::set_audit_sink(&counting_test_audit_sink);
                auto const before = g_test_audit_sink_invocations.load(std::memory_order_relaxed);
                merovingian::observability::log_diagnostic_audit("test_observability", "test.concurrent", {},
                                                                 merovingian::observability::LogEventSeverity::warning,
                                                                 merovingian::observability::AuditSinkFields{});
                REQUIRE(g_test_audit_sink_invocations.load(std::memory_order_relaxed) == before + 1U);

                // Restore the process-wide sink. Other tests in this binary
                // (e.g. tests/unit/test_local_database_scope.cpp,
                // tests/unit/test_auth_session.cpp) depend on whichever real
                // sink was installed before this scenario ran; leaving our
                // test-only sink in place would silently break them.
                merovingian::observability::set_audit_sink(previous_sink);
            }
        }
    }
}
