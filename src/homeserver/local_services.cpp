// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/local_services.hpp"

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
        // dangling. The sink silently no-ops until the next install.
        if (database == nullptr || !database->opened)
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
    log_diagnostic("audit.append", {
                                       {"category",   std::string{observability::audit_category_name(category)}, false},
                                       {"event_type", std::string{event_type},                                   false},
                                       {"actor",      std::string{actor},                                        false},
                                       {"target",     std::string{target},                                       false},
                                       {"reason",     std::string{reason},                                       false}
    });
    database.audit_events.push_back(
        observability::make_audit_event(category, event_type, actor, target, reason, "local-vertical-slice"));
    std::ignore = database::append_audit_event(database.persistent_store,
                                               {observability::audit_category_name(category), std::string{event_type},
                                                std::string{actor}, std::string{target}, std::string{reason}});
}

auto log_diagnostic_audit(LocalDatabase& database, std::string_view logger, std::string_view event,
                          std::vector<observability::StructuredLogField> fields,
                          observability::LogEventSeverity severity, observability::AuditCategory category,
                          std::string_view audit_event_type, std::string_view actor, std::string_view target,
                          std::string_view reason) -> void
{
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
    // installed exactly once; if multiple threads race, the function
    // pointer is a plain write that is safe under TSan.
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
