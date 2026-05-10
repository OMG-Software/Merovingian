// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/observability/observability.hpp>

#include <algorithm>
#include <string>
#include <utility>
#include <vector>

namespace merovingian::observability
{
namespace
{

[[nodiscard]] auto starts_with(std::string_view value, std::string_view prefix) noexcept -> bool
{
    return value.size() >= prefix.size() && value.substr(0U, prefix.size()) == prefix;
}

[[nodiscard]] auto exact_or_child(std::string_view target, std::string_view exact, std::string_view prefix) noexcept -> bool
{
    return target == exact || (target.size() > prefix.size() && starts_with(target, prefix));
}

[[nodiscard]] auto public_value(std::string_view value) -> database::BoundValue
{
    return {std::string{value}, false};
}

[[nodiscard]] auto route(std::string method, std::string path_template, AdminOperation operation) -> AdminRoute
{
    return {std::move(method), std::move(path_template), operation, true, {30U, 60U}};
}

[[nodiscard]] auto status_rank(HealthStatus status) noexcept -> std::uint8_t
{
    switch (status)
    {
    case HealthStatus::ok:
        return 0U;
    case HealthStatus::degraded:
        return 1U;
    case HealthStatus::failed:
        return 2U;
    }

    return 2U;
}

[[nodiscard]] auto worst_status(HealthStatus left, HealthStatus right) noexcept -> HealthStatus
{
    return status_rank(left) >= status_rank(right) ? left : right;
}

} // namespace

auto admin_surface_name(AdminSurface surface) noexcept -> char const*
{
    switch (surface)
    {
    case AdminSurface::local_socket:
        return "local_socket";
    case AdminSurface::loopback_http:
        return "loopback_http";
    }

    return "unknown";
}

auto admin_operation_name(AdminOperation operation) noexcept -> char const*
{
    switch (operation)
    {
    case AdminOperation::health:
        return "health";
    case AdminOperation::metrics:
        return "metrics";
    case AdminOperation::audit_query:
        return "audit_query";
    case AdminOperation::account_action:
        return "account_action";
    case AdminOperation::review_action:
        return "review_action";
    case AdminOperation::shutdown:
        return "shutdown";
    }

    return "unknown";
}

auto audit_category_name(AuditCategory category) noexcept -> char const*
{
    switch (category)
    {
    case AuditCategory::auth:
        return "auth";
    case AuditCategory::key_lifecycle:
        return "key_lifecycle";
    case AuditCategory::policy:
        return "policy";
    case AuditCategory::moderation:
        return "moderation";
    case AuditCategory::admin:
        return "admin";
    }

    return "unknown";
}

auto health_status_name(HealthStatus status) noexcept -> char const*
{
    switch (status)
    {
    case HealthStatus::ok:
        return "ok";
    case HealthStatus::degraded:
        return "degraded";
    case HealthStatus::failed:
        return "failed";
    }

    return "unknown";
}

auto admin_surface_is_safe(AdminControlSurface const& surface) noexcept -> bool
{
    if (!surface.enabled)
    {
        return true;
    }
    if (!surface.local_only || !surface.requires_admin_token)
    {
        return false;
    }
    if (surface.surface == AdminSurface::local_socket)
    {
        return surface.bind_address.empty() || starts_with(surface.bind_address, "/run/")
            || starts_with(surface.bind_address, "/var/run/");
    }
    return surface.bind_address == "127.0.0.1" || surface.bind_address == "::1";
}

auto admin_routes() -> std::vector<AdminRoute>
{
    return {
        route("GET", "/_merovingian/admin/health", AdminOperation::health),
        route("GET", "/_merovingian/admin/metrics", AdminOperation::metrics),
        route("GET", "/_merovingian/admin/audit", AdminOperation::audit_query),
        route("POST", "/_merovingian/admin/accounts/{userId}", AdminOperation::account_action),
        route("POST", "/_merovingian/admin/review/{targetType}/{targetId}", AdminOperation::review_action),
        route("POST", "/_merovingian/admin/shutdown", AdminOperation::shutdown),
    };
}

auto match_admin_route(std::string_view method, std::string_view target) -> AdminRouteMatch
{
    for (auto const& candidate : admin_routes())
    {
        if (candidate.method != method)
        {
            continue;
        }
        if (candidate.path_template == target)
        {
            return {true, candidate, {}};
        }
        if (candidate.operation == AdminOperation::account_action
            && exact_or_child(target, "/_merovingian/admin/accounts/{userId}", "/_merovingian/admin/accounts/"))
        {
            return {true, candidate, {}};
        }
        if (candidate.operation == AdminOperation::review_action)
        {
            auto constexpr prefix = std::string_view{"/_merovingian/admin/review/"};
            if (starts_with(target, prefix))
            {
                auto const suffix = target.substr(prefix.size());
                auto const separator = suffix.find('/');
                if (separator != std::string_view::npos && separator > 0U && separator + 1U < suffix.size()
                    && suffix.find('/', separator + 1U) == std::string_view::npos)
                {
                    return {true, candidate, {}};
                }
            }
        }
    }

    return {false, {}, "admin route not found"};
}

auto make_audit_event(
    AuditCategory category,
    std::string_view event_type,
    std::string_view actor,
    std::string_view target,
    std::string_view reason_code,
    std::string_view request_id
) -> AuditLogEvent
{
    return {category, std::string{event_type}, std::string{actor}, std::string{target}, std::string{reason_code}, std::string{request_id}, true};
}

auto audit_log_insert_statement(AuditLogEvent const& event) -> database::PreparedStatement
{
    return {
        "observability_append_audit_event",
        "INSERT INTO audit_log (category, event_type, actor, target, reason_code, request_id) VALUES ($1, $2, $3, $4, $5, $6)",
        {
            public_value(audit_category_name(event.category)),
            public_value(event.event_type),
            public_value(event.actor),
            public_value(event.target),
            public_value(event.reason_code),
            public_value(event.request_id),
        },
    };
}

auto audit_event_summary(AuditLogEvent const& event) -> std::string
{
    return "audit category=" + std::string{audit_category_name(event.category)} + " type=" + event.event_type
        + " actor=" + event.actor + " target=" + event.target + " reason=" + event.reason_code;
}

auto redact_log_value(StructuredLogField const& field) -> std::string
{
    return field.sensitive ? "<redacted>" : field.value;
}

auto structured_log_summary(StructuredLogEvent const& event) -> std::string
{
    auto summary = event.level + " " + event.logger;
    for (auto const& field : event.fields)
    {
        summary += " " + field.key + "=" + redact_log_value(field);
    }
    return summary;
}

auto logging_boundary_notes() -> std::vector<std::string>
{
    return {
        "Structured logs include request identifiers, actor identifiers, route names, and result codes.",
        "Structured logs must not include access tokens, refresh tokens, device keys, signing keys, event content, media bytes, or plaintext passwords.",
        "Sensitive structured fields are rendered as <redacted> before they leave the logging boundary.",
    };
}

auto metrics_are_safe(std::vector<MetricSample> const& metrics) noexcept -> bool
{
    return std::ranges::all_of(metrics, [](MetricSample const& metric) {
        return metric.secret_safe && !metric.name.empty();
    });
}

auto health_snapshot_summary(HealthCheckSnapshot const& snapshot) -> std::string
{
    auto summary = "health status=" + std::string{health_status_name(snapshot.status)};
    for (auto const& component : snapshot.components)
    {
        summary += " component=" + component.name + ':' + health_status_name(component.status);
    }
    return summary;
}

auto hardening_observability_summary(platform::HardeningSelfCheck const& check) -> std::vector<std::string>
{
    auto summaries = std::vector<std::string>{};
    summaries.reserve(check.checks().size());
    for (auto const& item : check.checks())
    {
        summaries.push_back("hardening " + item.name + '=' + platform::hardening_status_name(item.status));
    }
    return summaries;
}

auto make_observability_snapshot(
    HealthCheckSnapshot health,
    std::vector<MetricSample> metrics,
    platform::HardeningSelfCheck const& hardening
) -> ObservabilitySnapshot
{
    auto status = health.status;
    for (auto const& component : health.components)
    {
        status = worst_status(status, component.status);
    }
    health.status = status;
    return {std::move(health), std::move(metrics), hardening_observability_summary(hardening)};
}

auto observability_snapshot_is_safe(ObservabilitySnapshot const& snapshot) noexcept -> bool
{
    return metrics_are_safe(snapshot.metrics)
        && std::ranges::all_of(snapshot.hardening_summaries, [](std::string const& summary) {
               return !summary.empty();
           });
}

} // namespace merovingian::observability
