// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/observability/observability.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
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

    [[nodiscard]] auto exact_or_child(std::string_view target, std::string_view exact, std::string_view prefix) noexcept
        -> bool
    {
        return target == exact || (target.size() > prefix.size() && starts_with(target, prefix));
    }

    [[nodiscard]] auto public_value(std::string_view value) -> database::BoundValue
    {
        return {std::string{value}, false};
    }

    [[nodiscard]] auto route(std::string method, std::string path_template, AdminOperation operation) -> AdminRoute
    {
        return {
            std::move(method), std::move(path_template), operation, true, {30U, 60U}
        };
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

    [[nodiscard]] auto lower_ascii(std::string_view value) -> std::string
    {
        auto lowered = std::string{};
        lowered.reserve(value.size());
        for (auto const character : value)
        {
            lowered.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(character))));
        }
        return lowered;
    }

    [[nodiscard]] auto contains_sensitive_marker(std::string_view key) -> bool
    {
        auto const lowered = lower_ascii(key);
        if (lowered == "body" || lowered.ends_with("_body") || lowered == "authorization" || lowered == "password" ||
            lowered == "secret" || lowered == "session")
        {
            return true;
        }
        for (auto const marker :
             {"access_token", "refresh_token", "password", "secret", "session_token", "signature", "event_content",
              "content_json", "media_bytes", "device_keys", "one_time_keys", "fallback_keys"})
        {
            if (lowered.find(marker) != std::string::npos)
            {
                return true;
            }
        }
        return false;
    }

    [[nodiscard]] auto hex_encode(std::uint64_t value, std::size_t width) -> std::string
    {
        auto output = std::string(width, '0');
        for (auto index = std::size_t{0U}; index < width; ++index)
        {
            auto const nibble = static_cast<unsigned>(value & 0xFU);
            output[width - 1U - index] = static_cast<char>(nibble < 10U ? '0' + nibble : 'a' + (nibble - 10U));
            value >>= 4U;
        }
        return output;
    }

    [[nodiscard]] auto escape_prometheus(std::string_view value) -> std::string
    {
        auto escaped = std::string{};
        escaped.reserve(value.size());
        for (auto const character : value)
        {
            switch (character)
            {
            case '\\':
                escaped += "\\\\";
                break;
            case '"':
                escaped += "\\\"";
                break;
            case '\n':
                escaped += "\\n";
                break;
            default:
                escaped.push_back(character);
                break;
            }
        }
        return escaped;
    }

    [[nodiscard]] auto label_name_is_safe(std::string_view value) noexcept -> bool
    {
        if (value.empty())
        {
            return false;
        }
        return std::ranges::all_of(value, [](char const character) {
            return std::isalnum(static_cast<unsigned char>(character)) != 0 || character == '_' || character == ':';
        });
    }

    [[nodiscard]] auto metric_name_is_safe(std::string_view value) noexcept -> bool
    {
        return label_name_is_safe(value);
    }

    auto correlation_slot() noexcept -> CorrelationContext const*&
    {
        thread_local auto* context = static_cast<CorrelationContext const*>(nullptr);
        return context;
    }

    [[nodiscard]] auto sanitize_query(std::string_view query) -> std::string
    {
        auto output = std::string{};
        auto remaining = query;
        auto first = true;
        while (!remaining.empty())
        {
            auto const ampersand = remaining.find('&');
            auto const segment = remaining.substr(0U, ampersand);
            auto const equals = segment.find('=');
            auto const key = equals == std::string_view::npos ? segment : segment.substr(0U, equals);
            auto const value = equals == std::string_view::npos ? std::string_view{} : segment.substr(equals + 1U);
            if (!first)
            {
                output.push_back('&');
            }
            first = false;
            output.append(key);
            if (equals != std::string_view::npos)
            {
                output.push_back('=');
                output.append(contains_sensitive_marker(key) ? std::string_view{"<redacted>"} : value);
            }
            if (ampersand == std::string_view::npos)
            {
                break;
            }
            remaining = remaining.substr(ampersand + 1U);
        }
        return output;
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

auto audit_category_from_name(std::string_view name) noexcept -> std::optional<AuditCategory>
{
    // Inverse of `audit_category_name`. Used by the audit-filter
    // helper to turn `?category=policy` query parameters into the
    // enum. Unknown names return `std::nullopt` so the caller can
    // return 400 with a clear "unknown audit category: <name>"
    // message rather than silently dropping the request.
    if (name == "auth")
    {
        return AuditCategory::auth;
    }
    if (name == "key_lifecycle")
    {
        return AuditCategory::key_lifecycle;
    }
    if (name == "policy")
    {
        return AuditCategory::policy;
    }
    if (name == "moderation")
    {
        return AuditCategory::moderation;
    }
    if (name == "admin")
    {
        return AuditCategory::admin;
    }
    return std::nullopt;
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

auto metric_type_name(MetricType type) noexcept -> char const*
{
    switch (type)
    {
    case MetricType::counter:
        return "counter";
    case MetricType::gauge:
        return "gauge";
    }

    return "gauge";
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
        return surface.bind_address.empty() || starts_with(surface.bind_address, "/run/") ||
               starts_with(surface.bind_address, "/var/run/");
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
        if (candidate.operation == AdminOperation::account_action &&
            exact_or_child(target, "/_merovingian/admin/accounts/{userId}", "/_merovingian/admin/accounts/"))
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
                if (separator != std::string_view::npos && separator > 0U && separator + 1U < suffix.size() &&
                    suffix.find('/', separator + 1U) == std::string_view::npos)
                {
                    return {true, candidate, {}};
                }
            }
        }
    }

    return {false, {}, "admin route not found"};
}

auto make_audit_event(AuditCategory category, std::string_view event_type, std::string_view actor,
                      std::string_view target, std::string_view reason_code, std::string_view request_id)
    -> AuditLogEvent
{
    return {category,
            std::string{event_type},
            std::string{actor},
            std::string{target},
            std::string{reason_code},
            std::string{request_id},
            true};
}

auto audit_log_insert_statement(AuditLogEvent const& event) -> database::PreparedStatement
{
    return {
        "observability_append_audit_event",
        "INSERT INTO audit_log (category, event_type, actor, target, reason_code, request_id) VALUES ($1, $2, $3, $4, "
        "$5, $6)",
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
    return "audit category=" + std::string{audit_category_name(event.category)} + " type=" + event.event_type +
           " actor=" + event.actor + " target=" + event.target + " reason=" + event.reason_code;
}

auto log_field_is_sensitive(std::string_view key) -> bool
{
    return contains_sensitive_marker(key);
}

auto sanitized_http_target(std::string_view target) -> std::string
{
    auto const query_start = target.find('?');
    if (query_start == std::string_view::npos)
    {
        return std::string{target};
    }
    auto sanitized = std::string{target.substr(0U, query_start)};
    sanitized.push_back('?');
    sanitized.append(sanitize_query(target.substr(query_start + 1U)));
    return sanitized;
}

auto redact_log_value(StructuredLogField const& field) -> std::string
{
    return field.sensitive || log_field_is_sensitive(field.key) ? "<redacted>" : field.value;
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

auto diagnostic_log_summary(std::string_view logger, std::string_view event, std::vector<StructuredLogField> fields)
    -> std::string
{
    fields.insert(fields.begin(), {"event", std::string{event}, false});
    return structured_log_summary({std::string{logger}, "debug", std::move(fields)});
}

auto make_correlation_context(std::uint64_t sequence) -> CorrelationContext
{
    auto const request = hex_encode(sequence, 16U);
    auto const trace = hex_encode(sequence, 16U) + hex_encode(sequence ^ 0x9e3779b97f4a7c15ULL, 16U);
    auto const span = hex_encode(sequence ^ 0xa5a5a5a5a5a5a5a5ULL, 16U);
    return {
        "req-" + request,
        std::move(trace),
        std::move(span),
    };
}

auto current_correlation_context() noexcept -> CorrelationContext const*
{
    return correlation_slot();
}

auto with_correlation_fields(CorrelationContext const& context, std::vector<StructuredLogField> fields)
    -> std::vector<StructuredLogField>
{
    fields.insert(fields.begin(), {
                                      {"span_id",    context.span_id,    false},
                                      {"trace_id",   context.trace_id,   false},
                                      {"request_id", context.request_id, false},
    });
    return fields;
}

auto logging_boundary_notes() -> std::vector<std::string>
{
    return {
        "Structured logs include request identifiers, trace identifiers, span identifiers, actor identifiers, route "
        "names, and result codes.",
        "Structured logs must not include access tokens, refresh tokens, device keys, signing keys, event content, "
        "media bytes, request bodies, signatures, authorization headers, or plaintext passwords.",
        "Sensitive structured fields are rendered as <redacted> before they leave the logging boundary.",
    };
}

auto metrics_are_safe(std::vector<MetricSample> const& metrics) noexcept -> bool
{
    return std::ranges::all_of(metrics, [](MetricSample const& metric) {
        if (!metric.secret_safe || !metric_name_is_safe(metric.name))
        {
            return false;
        }
        return std::ranges::all_of(metric.labels, [](MetricLabel const& label) {
            return label.secret_safe && label_name_is_safe(label.key);
        });
    });
}

auto prometheus_metrics_summary(std::vector<MetricSample> const& metrics) -> std::string
{
    auto output = std::string{};
    auto documented = std::vector<std::string>{};
    for (auto const& metric : metrics)
    {
        if (!metric.secret_safe || !metric_name_is_safe(metric.name))
        {
            continue;
        }

        if (!std::ranges::any_of(documented, [&metric](std::string const& name) {
                return name == metric.name;
            }))
        {
            documented.push_back(metric.name);
            if (!metric.help.empty())
            {
                output += "# HELP " + metric.name + ' ' + escape_prometheus(metric.help) + '\n';
            }
            output += "# TYPE " + metric.name + ' ' + std::string{metric_type_name(metric.type)} + '\n';
        }

        output += metric.name;
        auto first_label = true;
        for (auto const& label : metric.labels)
        {
            if (!label.secret_safe || !label_name_is_safe(label.key))
            {
                continue;
            }
            output += first_label ? "{" : ",";
            first_label = false;
            output += label.key + "=\"" + escape_prometheus(label.value) + "\"";
        }
        if (!first_label)
        {
            output.push_back('}');
        }
        output += ' ';
        output += std::to_string(metric.value);
        output.push_back('\n');
    }
    return output;
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

auto make_observability_snapshot(HealthCheckSnapshot health, std::vector<MetricSample> metrics,
                                 platform::HardeningSelfCheck const& hardening) -> ObservabilitySnapshot
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
    return metrics_are_safe(snapshot.metrics) &&
           std::ranges::all_of(snapshot.hardening_summaries, [](std::string const& summary) {
               return !summary.empty();
           });
}

CorrelationScope::CorrelationScope(CorrelationContext const& context) noexcept
    : previous_{correlation_slot()}
{
    correlation_slot() = &context;
}

CorrelationScope::~CorrelationScope()
{
    correlation_slot() = previous_;
}

} // namespace merovingian::observability
