// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::observability
{

enum class AdminSurface
{
    local_socket,
    loopback_http,
};

// One value per operator route this server serves under /_merovingian/admin/. The table behind
// admin_routes() is the only list of them (ADR-0504): the dispatcher, the local router and the rate
// limiter's counter key all read it. There is deliberately no operation that stops the server
// (ADR-0505).
enum class AdminOperation
{
    health,
    metrics,
    media_metrics,
    audit_query,
    account_summary,
    account_action,
    review_action,
    media_quarantine,
    media_release,
    media_remove,
};

enum class AuditCategory
{
    auth,
    key_lifecycle,
    policy,
    moderation,
    admin,
};

enum class HealthStatus
{
    ok,
    degraded,
    failed,
};

enum class MetricType
{
    counter,
    gauge,
};

} // namespace merovingian::observability
