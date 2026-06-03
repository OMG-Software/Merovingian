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
// (see `merovingian::observability::log_diagnostic_audit`). Called by
// `start_homeserver()` so modules below `homeserver/` (notably
// `auth/registration_policy`) can route audit rows through the same
// code path. Pass `nullptr` to detach.
auto install_local_audit_database(LocalDatabase* database) noexcept -> void;

// Variant of `install_local_audit_database` that also returns the
// previously-installed pointer. Implementation detail of
// `LocalDatabaseScope`; not part of the public API.
auto install_local_audit_database_returning_previous(LocalDatabase* database) noexcept -> LocalDatabase*;

// RAII scope guard that wires the active `LocalDatabase` into the
// audit sink on construction and restores the prior install on
// destruction. Use this at any call site that holds a
// `HomeserverRuntime` for the duration of a region of code that may
// route audit rows (`log_diagnostic_audit` -> `local_audit_sink` ->
// `append_local_audit`). The destructor restores the previous sink
// install, so a succeeding test scenario cannot leak a now-dangling
// database pointer into the next one.
//
// `start_client_server` already installs the sink for the common case
// (the 250+ unit test scenarios in `test_client_server*.cpp` plus
// `main.cpp`'s production entry). Use `LocalDatabaseScope` at any
// site that constructs a runtime outside that path — e.g. the
// integration test scenario that calls `start_runtime` directly.
class LocalDatabaseScope final
{
  public:
    explicit LocalDatabaseScope(LocalDatabase& database) noexcept
        : m_previous{install_local_audit_database_returning_previous(&database)}
    {
    }
    ~LocalDatabaseScope() noexcept
    {
        install_local_audit_database(m_previous);
    }

    LocalDatabaseScope(LocalDatabaseScope const&) = delete;
    auto operator=(LocalDatabaseScope const&) -> LocalDatabaseScope& = delete;
    LocalDatabaseScope(LocalDatabaseScope&&) = delete;
    auto operator=(LocalDatabaseScope&&) -> LocalDatabaseScope& = delete;

  private:
    LocalDatabase* m_previous{nullptr};
};

// Test-only accessors for the audit-sink database pointer. Production
// code uses `install_local_audit_database` to set it; tests read it
// back to assert the sink was wired up. Not part of the public API.
[[nodiscard]] auto current_audit_database() noexcept -> LocalDatabase*;
auto set_current_audit_database(LocalDatabase* database) noexcept -> void;

} // namespace merovingian::homeserver
