// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/local_services.hpp"

#include "merovingian/database/bounded_text.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"

#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace merovingian::homeserver
{
namespace
{

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields,
                        observability::LogEventSeverity severity = observability::LogEventSeverity::debug) -> void
    {
        observability::log_diagnostic("local_services", event, fields, severity);
    }

    // Thread-local pointer to the active LocalDatabase used by the
    // audit sink. Set by `install_local_audit_database` at server
    // start. A thread_local keeps the sink's call from racing with
    // the per-thread runtime install/remove cycle, and avoids a
    // global mutex on the hot path.
    auto thread_audit_database() noexcept -> LocalDatabase*&
    {
        thread_local auto* database = static_cast<LocalDatabase*>(nullptr);
        return database;
    }

    // L-10 (security-audit-report-2026-09.md): tracks whether
    // `local_audit_sink` is currently in a run of drops on *this* thread,
    // so a flood of audit-worthy events while the sink is unavailable
    // produces exactly one warning, not one per dropped event. thread_local
    // to match `thread_audit_database()` -- no cross-thread synchronization
    // needed, and a per-thread episode is the right granularity since the
    // install/teardown state this policy tracks is itself thread_local.
    auto local_audit_sink_drop_policy() noexcept -> observability::DropEpisodePolicy&
    {
        thread_local auto policy = observability::DropEpisodePolicy{};
        return policy;
    }

    // Sink that forwards to `append_local_audit`. Installed once at
    // process start; the homeserver stores a thread-local pointer to
    // the active `LocalDatabase` so the sink can call
    // `append_local_audit`. The indirection lets modules below
    // `homeserver/` (notably `auth/`) emit audit rows through the
    // same code path without taking a dependency on `LocalDatabase`.
    // See `merovingian::observability::log_diagnostic_audit` for the
    // helper.
    auto local_audit_sink(observability::AuditSinkFields const& fields) -> void
    {
        auto* database = thread_audit_database();
        // Defensive null/closed check: a previous `start_runtime` may
        // have torn down a LocalDatabase and the next test or hot
        // reload is about to install a new one. A closed `LocalDatabase`
        // is a sign that the previous owner is gone and the pointer is
        // dangling. The sink no-ops until the next install; this was
        // previously silent (L-10) -- it now warns once per drop episode
        // via the diagnostic log so an operator can see that durable
        // audit persistence, not just the event itself, was lost.
        auto const available = database != nullptr && database->opened;
        if (local_audit_sink_drop_policy().observe(available))
        {
            observability::log_diagnostic(
                "local_services", "audit.dropped",
                {
                    {"event_type", std::string{fields.event_type},                                   false},
                    {"category",   std::string{observability::audit_category_name(fields.category)}, false},
            },
                observability::LogEventSeverity::warning);
        }
        if (!available)
        {
            return;
        }
        append_local_audit(*database, fields.category, fields.event_type, fields.actor, fields.target, fields.reason);
    }

    auto ensure_audit_sink_installed() -> bool
    {
        static auto const installed = []() {
            observability::set_audit_sink(&local_audit_sink);
            return true;
        }();
        return installed;
    }

} // namespace

[[nodiscard]] auto make_operation_result(bool ok, std::string value, std::string reason, std::uint16_t status)
    -> OperationResult
{
    auto const resolved_status = status == 0U ? static_cast<std::uint16_t>(ok ? 200U : 400U) : status;
    return {ok, resolved_status, std::move(value), std::move(reason)};
}

auto append_local_audit(LocalDatabase& database, observability::AuditCategory category, std::string_view event_type,
                        std::string_view actor, std::string_view target, std::string_view reason) -> void
{
    // AUTH-1 (ADR-0080): per-request rejections that any unauthenticated client
    // can trigger are rate-capped per kind. A suppressed event is only counted;
    // its diagnostic log line was already emitted by the caller, and the count
    // rides on the next row the kind is allowed to write.
    auto const admission = database.audit_rate_gate.admit(event_type);
    if (!admission.write)
    {
        return;
    }
    // AUTH-1: actor, target and reason can carry client-supplied text (a login
    // `user`, a request target). Bound and sanitise them once, here, so the log
    // line, the in-memory window and the durable row all see the same value.
    auto const safe_actor = database::bounded_utf8(actor, database::max_audit_field_bytes);
    auto const safe_target = database::bounded_utf8(target, database::max_audit_field_bytes);
    auto const safe_reason = [&]() {
        if (admission.suppressed == 0U)
        {
            return database::bounded_utf8(reason, database::max_audit_field_bytes);
        }
        auto const suffix = " suppressed=" + std::to_string(admission.suppressed);
        return database::bounded_utf8(reason, database::max_audit_field_bytes - suffix.size()) + suffix;
    }();
    log_diagnostic("audit.append", {
                                       {"category",   std::string{observability::audit_category_name(category)}, false},
                                       {"event_type", std::string{event_type},                                   false},
                                       {"actor",      safe_actor,                                                false},
                                       {"target",     safe_target,                                               false},
                                       {"reason",     safe_reason,                                               false}
    });
    database.audit_events.push_back(observability::make_audit_event(category, event_type, safe_actor, safe_target,
                                                                    safe_reason, "local-vertical-slice"));
    while (database.audit_events.size() > database::max_in_memory_audit_events)
    {
        database.audit_events.pop_front();
    }
    std::ignore = database::append_audit_event(
        database.persistent_store,
        {observability::audit_category_name(category), std::string{event_type}, safe_actor, safe_target, safe_reason});
}

auto log_diagnostic_audit(LocalDatabase& database, std::string_view logger, std::string_view event,
                          std::vector<observability::StructuredLogField> fields,
                          observability::LogEventSeverity severity, observability::AuditCategory category,
                          std::string_view audit_event_type, std::string_view actor, std::string_view target,
                          std::string_view reason) -> void
{
    // AUTH-1: a diagnostic field can hold client-supplied text (a login `user`,
    // a request target), so cap each value before it is written to the log.
    for (auto& field : fields)
    {
        if (field.value.size() > database::max_audit_field_bytes)
        {
            field.value = database::bounded_utf8(field.value, database::max_audit_field_bytes);
        }
    }
    // Always emit the diagnostic line. The helper takes ownership of
    // `fields` so the call site does not have to clone it twice.
    observability::log_diagnostic(logger, event, fields, severity);
    // Route severity >= warning to the audit log. Today the only
    // callers pass LogEventSeverity::warning, so the audit table sees
    // exactly the high-signal failures the design doc promised. A
    // future caller that wants `error` will get the same routing
    // automatically because of the static_cast<int> comparison.
    if (static_cast<int>(severity) >= static_cast<int>(observability::LogEventSeverity::warning))
    {
        append_local_audit(database, category, audit_event_type, actor, target, reason);
    }
}

auto install_local_audit_database(LocalDatabase* database) noexcept -> void
{
    // First-call install of the audit sink; subsequent calls just
    // point the thread-local database pointer. The sink function is
    // installed exactly once; if multiple threads race, the write goes
    // through `observability::set_audit_sink`'s atomic store (L-09), so
    // it is race-free under TSan regardless of call order.
    std::ignore = ensure_audit_sink_installed();
    thread_audit_database() = database;
}

auto current_audit_database() noexcept -> LocalDatabase*
{
    return thread_audit_database();
}

auto set_current_audit_database(LocalDatabase* database) noexcept -> void
{
    thread_audit_database() = database;
}

} // namespace merovingian::homeserver
