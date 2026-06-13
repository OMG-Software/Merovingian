// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::homeserver
{

[[nodiscard]] auto make_operation_result(bool ok, std::string value, std::string reason = {}, std::uint16_t status = 0U)
    -> OperationResult;

auto append_local_audit(LocalDatabase& database, observability::AuditCategory category, std::string_view event_type,
                        std::string_view actor, std::string_view target, std::string_view reason) -> void;

// Combined diagnostic + audit-routing helper (0.5.0). The five
// high-signal failure call sites (rate_limit.exceeded, login.rejected,
// access_token.rejected, request.rejected, registration_policy.denied)
// all need to (a) emit a structured log line at the requested severity
// and (b) write a row to `audit_log` so an operator can query the audit
// surface. Without this helper every call site duplicated the same
// ten-line ceremony; with it, the call site is one line and the
// severity->audit-routing rule lives in one place.
//
// Routing rule: severity >= warning writes a row to audit_log (with the
// supplied category/event_type/reason). severity < warning only emits
// the log line. The decision matches the design doc's "follow-up
// routing" promise from PR #190.
auto log_diagnostic_audit(LocalDatabase& database, std::string_view logger, std::string_view event,
                          std::vector<observability::StructuredLogField> fields, observability::LogEventSeverity severity,
                          observability::AuditCategory category, std::string_view audit_event_type,
                          std::string_view actor, std::string_view target, std::string_view reason) -> void;

// Install the active `LocalDatabase` pointer used by the audit sink
// (see `merovingian::observability::log_diagnostic_audit`). Pass
// `nullptr` to detach. The install is stored in a thread_local so the
// audit-sink call site (which lives in a module below `homeserver/`)
// can route through the same code path without taking a dependency
// on `LocalDatabase`. See `LocalDatabaseScope` for the RAII wrapper
// that binds the install to a runtime's lifetime.
auto install_local_audit_database(LocalDatabase* database) noexcept -> void;

// Test-only accessor for the audit-sink database pointer. Production
// code uses `install_local_audit_database` to set it; tests read it
// back to assert the sink was wired up. The `LocalDatabaseScope`
// dtor uses it to check whether the install still belongs to this
// scope before clearing, so the forward-declaration must precede
// the class definition.
[[nodiscard]] auto current_audit_database() noexcept -> LocalDatabase*;
auto set_current_audit_database(LocalDatabase* database) noexcept -> void;

// RAII scope guard that wires the active `LocalDatabase` into the
// audit sink on construction and *clears* the install on destruction
// (if the install still belongs to this scope). The lifetime is bound
// to the scope object's identity, so any other code that takes over
// the install (a move of the owning runtime, a `reset()` re-seat, or
// a later scope at an inner block) disables the dtor's clear: a
// scope is only allowed to undo an install it actually owns.
//
// The intended owner is `HomeserverRuntime`, which embeds a
// `std::unique_ptr<LocalDatabaseScope> audit_sink_scope` as a member
// so the install is installed on runtime construction and cleared on
// runtime destruction — no call site needs to remember it. Storing
// the `LocalDatabase&` by address means the dtor can compare against
// the current thread_local and avoid clearing an install that
// belongs to a different (e.g. moved-into) scope.
//
// The dtor is a no-op when `current_audit_database() != m_installed`
// so the move ctor of `HomeserverRuntime` can construct a fresh
// scope (re-installing on the new `database`) without the source's
// scope tearing it down. `reset()` re-seats the install when the
// database member is replaced by move-assignment.
class LocalDatabaseScope final
{
  public:
    explicit LocalDatabaseScope(LocalDatabase& database) noexcept
        : m_installed{&database}
    {
        install_local_audit_database(m_installed);
    }
    ~LocalDatabaseScope() noexcept
    {
        if (current_audit_database() == m_installed)
        {
            install_local_audit_database(nullptr);
        }
    }

    // Re-seat the scope on a new `LocalDatabase` (e.g. after the
    // owning runtime's `database` member is replaced by a move). The
    // old install is cleared only if it is still the active one; the
    // new install then takes its place. Safe to call multiple times
    // on the same scope object.
    auto reset(LocalDatabase& database) noexcept -> void
    {
        if (current_audit_database() == m_installed)
        {
            install_local_audit_database(nullptr);
        }
        m_installed = &database;
        install_local_audit_database(m_installed);
    }

    LocalDatabaseScope(LocalDatabaseScope const&) = delete;
    auto operator=(LocalDatabaseScope const&) -> LocalDatabaseScope& = delete;
    LocalDatabaseScope(LocalDatabaseScope&&) = delete;
    auto operator=(LocalDatabaseScope&&) -> LocalDatabaseScope& = delete;

  private:
    LocalDatabase* m_installed{nullptr};
};

} // namespace merovingian::homeserver
