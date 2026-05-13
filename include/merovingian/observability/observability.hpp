// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/statement.hpp"
#include "merovingian/http/rate_limit.hpp"
#include "merovingian/platform/hardening_self_check.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::observability
{

enum class AdminSurface
{
    local_socket,
    loopback_http,
};

enum class AdminOperation
{
    health,
    metrics,
    audit_query,
    account_action,
    review_action,
    shutdown,
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

struct AdminControlSurface final
{
    AdminSurface surface{AdminSurface::local_socket};
    std::string bind_address{};
    bool enabled{false};
    bool local_only{true};
    bool requires_admin_token{true};
    bool tls_required{false};
};

struct AdminRoute final
{
    std::string method{};
    std::string path_template{};
    AdminOperation operation{AdminOperation::health};
    bool requires_admin{true};
    http::RateLimitPolicy rate_limit{};
};

struct AdminRouteMatch final
{
    bool matched{false};
    AdminRoute route{};
    std::string reason{};
};

struct AuditLogEvent final
{
    AuditCategory category{AuditCategory::admin};
    std::string event_type{};
    std::string actor{};
    std::string target{};
    std::string reason_code{};
    std::string request_id{};
    bool append_only{true};
};

struct StructuredLogField final
{
    std::string key{};
    std::string value{};
    bool sensitive{false};
};

struct StructuredLogEvent final
{
    std::string logger{};
    std::string level{};
    std::vector<StructuredLogField> fields{};
};

struct MetricSample final
{
    std::string name{};
    std::int64_t value{0};
    bool secret_safe{true};
};

struct HealthCheckComponent final
{
    std::string name{};
    HealthStatus status{HealthStatus::ok};
    std::string summary{};
};

struct HealthCheckSnapshot final
{
    HealthStatus status{HealthStatus::ok};
    std::vector<HealthCheckComponent> components{};
};

struct ObservabilitySnapshot final
{
    HealthCheckSnapshot health{};
    std::vector<MetricSample> metrics{};
    std::vector<std::string> hardening_summaries{};
};

[[nodiscard]] auto admin_surface_name(AdminSurface surface) noexcept -> char const*;
[[nodiscard]] auto admin_operation_name(AdminOperation operation) noexcept -> char const*;
[[nodiscard]] auto audit_category_name(AuditCategory category) noexcept -> char const*;
[[nodiscard]] auto health_status_name(HealthStatus status) noexcept -> char const*;
[[nodiscard]] auto admin_surface_is_safe(AdminControlSurface const& surface) noexcept -> bool;
[[nodiscard]] auto admin_routes() -> std::vector<AdminRoute>;
[[nodiscard]] auto match_admin_route(std::string_view method, std::string_view target) -> AdminRouteMatch;
[[nodiscard]] auto make_audit_event(
    AuditCategory category,
    std::string_view event_type,
    std::string_view actor,
    std::string_view target,
    std::string_view reason_code,
    std::string_view request_id
) -> AuditLogEvent;
[[nodiscard]] auto audit_log_insert_statement(AuditLogEvent const& event) -> database::PreparedStatement;
[[nodiscard]] auto audit_event_summary(AuditLogEvent const& event) -> std::string;
[[nodiscard]] auto redact_log_value(StructuredLogField const& field) -> std::string;
[[nodiscard]] auto structured_log_summary(StructuredLogEvent const& event) -> std::string;
[[nodiscard]] auto logging_boundary_notes() -> std::vector<std::string>;
[[nodiscard]] auto metrics_are_safe(std::vector<MetricSample> const& metrics) noexcept -> bool;
[[nodiscard]] auto health_snapshot_summary(HealthCheckSnapshot const& snapshot) -> std::string;
[[nodiscard]] auto hardening_observability_summary(platform::HardeningSelfCheck const& check)
    -> std::vector<std::string>;
[[nodiscard]] auto make_observability_snapshot(
    HealthCheckSnapshot health,
    std::vector<MetricSample> metrics,
    platform::HardeningSelfCheck const& hardening
) -> ObservabilitySnapshot;
[[nodiscard]] auto observability_snapshot_is_safe(ObservabilitySnapshot const& snapshot) noexcept -> bool;

} // namespace merovingian::observability
