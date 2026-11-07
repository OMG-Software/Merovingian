// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/LocalDatabase.hpp"
#include "merovingian/homeserver/LocalDatabaseScope.hpp" // split-shim
#include "merovingian/homeserver/OperationResult.hpp"
#include "merovingian/observability/AuditCategory.hpp"
#include "merovingian/observability/StructuredLogField.hpp"
#include "merovingian/observability/logger.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::homeserver
{

[[nodiscard]] auto make_operation_result(bool ok, std::string value, std::string reason = {},
                                         std::uint16_t status = 0U) -> OperationResult;

auto append_local_audit(LocalDatabase& database, observability::AuditCategory category, std::string_view event_type,
                        std::string_view actor, std::string_view target, std::string_view reason) -> void;

// Updates the bounded runtime audit mirror and diagnostic log without a
// database write or admission decision. Callers own persistence and admission;
// transactional moderation invokes this only after its required audit commits.
auto remember_local_audit(LocalDatabase& database, observability::AuditCategory category, std::string_view event_type,
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
                          std::vector<observability::StructuredLogField> fields,
                          observability::LogEventSeverity severity, observability::AuditCategory category,
                          std::string_view audit_event_type, std::string_view actor, std::string_view target,
                          std::string_view reason) -> void;

} // namespace merovingian::homeserver
