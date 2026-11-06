// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/observability/AuditCategory.hpp"

#include <string>

namespace merovingian::observability
{

// NOTE (L-11, security-audit-report-2026-09.md): this struct previously
// carried an `append_only` flag initialized to `true` that nothing ever
// consulted -- `audit_log_insert_statement()` never emits anything but
// INSERT, so the flag asserted a guarantee the code did not actually
// enforce. The only real enforcement point is a database-level trigger
// rejecting UPDATE/DELETE on `audit_log`, which belongs in a migration
// and is out of scope here. Rather than keep a field that lies about a
// guarantee, it was removed; `audit_log_insert_statement()` below is the
// append-only guarantee that actually exists today.
struct AuditLogEvent final
{
    AuditCategory category{AuditCategory::admin};
    std::string event_type{};
    std::string actor{};
    std::string target{};
    std::string reason_code{};
    std::string request_id{};
};

} // namespace merovingian::observability
