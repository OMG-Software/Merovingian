// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/statement.hpp"
#include "merovingian/http/rate_limit.hpp"
#include "merovingian/platform/hardening_self_check.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
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

enum class MetricType
{
    counter,
    gauge,
};

struct MetricLabel final
{
    std::string key{};
    std::string value{};
    bool secret_safe{true};
};

struct MetricSample final
{
    std::string name{};
    std::int64_t value{0};
    bool secret_safe{true};
    MetricType type{MetricType::gauge};
    std::string help{};
    std::vector<MetricLabel> labels{};
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

struct CorrelationContext final
{
    std::string request_id{};
    std::string trace_id{};
    std::string span_id{};
};

class CorrelationScope final
{
public:
    explicit CorrelationScope(CorrelationContext const& context) noexcept;
    CorrelationScope(CorrelationScope const& other) = delete;
    auto operator=(CorrelationScope const& other) -> CorrelationScope& = delete;
    CorrelationScope(CorrelationScope&& other) = delete;
    auto operator=(CorrelationScope&& other) -> CorrelationScope& = delete;
    ~CorrelationScope();

private:
    CorrelationContext const* previous_{nullptr};
};

[[nodiscard]] auto admin_surface_name(AdminSurface surface) noexcept -> char const*;
[[nodiscard]] auto admin_operation_name(AdminOperation operation) noexcept -> char const*;
[[nodiscard]] auto audit_category_name(AuditCategory category) noexcept -> char const*;
[[nodiscard]] auto audit_category_from_name(std::string_view name) noexcept -> std::optional<AuditCategory>;
[[nodiscard]] auto health_status_name(HealthStatus status) noexcept -> char const*;
[[nodiscard]] auto metric_type_name(MetricType type) noexcept -> char const*;
[[nodiscard]] auto admin_surface_is_safe(AdminControlSurface const& surface) noexcept -> bool;
[[nodiscard]] auto admin_routes() -> std::vector<AdminRoute>;
[[nodiscard]] auto match_admin_route(std::string_view method, std::string_view target) -> AdminRouteMatch;
[[nodiscard]] auto make_audit_event(AuditCategory category, std::string_view event_type, std::string_view actor,
                                    std::string_view target, std::string_view reason_code, std::string_view request_id)
    -> AuditLogEvent;
[[nodiscard]] auto audit_log_insert_statement(AuditLogEvent const& event) -> database::PreparedStatement;
[[nodiscard]] auto audit_event_summary(AuditLogEvent const& event) -> std::string;
[[nodiscard]] auto log_field_is_sensitive(std::string_view key) -> bool;
[[nodiscard]] auto sanitized_http_target(std::string_view target) -> std::string;
[[nodiscard]] auto redact_log_value(StructuredLogField const& field) -> std::string;
// M-11 (security-audit-report-2026-09.md): redacts `key=value` tokens in a
// freeform log message when `key` matches the same sensitivity rules as
// structured fields (see `log_field_is_sensitive`/`contains_sensitive_marker`).
// This is the redaction boundary the legacy LOG_*/LOGF_* macros route through
// at the `SingleLog` level (see logger.hpp), so no call site can bypass it by
// building a plain std::string instead of using StructuredLogField. Tokens
// are whitespace-delimited; a sensitive value that itself contains embedded
// whitespace is only redacted up to the first space, matching the "key=value"
// shape used by every current LOG_*/LOGF_* call site (e.g. "shard=0
// config=/etc/x").
[[nodiscard]] auto redact_log_message(std::string_view message) -> std::string;
// AUTH-9 (security-audit-report-2026-09-29.md): renders control characters as
// printable escapes so a logged value cannot forge an extra log line or send a
// terminal control sequence to an operator's console. `\n`, `\r` and `\t` become
// those two-character escapes, every other C0 control and DEL becomes `\xHH`,
// and a UTF-8 encoded C1 control (U+0080-U+009F) becomes `\u00HH`. All other
// bytes, including the rest of UTF-8, pass through unchanged. `SingleLog`
// applies it to every line it writes (see logger.hpp).
[[nodiscard]] auto escape_log_controls(std::string_view text) -> std::string;
// AUTH-9 (security-audit-report-2026-09-29.md): the longest a single structured
// log field value may be in the emitted line. A client controls values such as a
// login `identifier.user` or `device_id`; without a cap one request could write
// a megabyte into every log line that mentions it. The bound is on the bytes
// that reach the log, that is the value AFTER `escape_log_controls`, so a value
// full of control characters (each up to four bytes escaped) cannot expand past
// it. Keys and event names are chosen by developers, never by a client, so they
// are not capped.
inline constexpr auto max_log_field_value_bytes = std::size_t{2048U};
// Cuts `value` so its escaped form is at most `max_log_field_value_bytes`, on a
// code-point boundary (a multi-byte UTF-8 sequence, and a whole escape such as
// `\x1b`, is kept or dropped as a unit) and appends the ASCII marker
// `...[truncated N bytes]`, where N is the number of bytes of `value` dropped.
// A value whose escaped form fits is returned unchanged. The result is still
// unescaped text: `SingleLog` escapes it once at the sink, and the marker holds
// nothing the escaper changes, so the emitted value is the bounded prefix plus
// the marker (at most the cap plus about 40 bytes).
[[nodiscard]] auto cap_log_field_value(std::string_view value) -> std::string;
// The text a structured field contributes after `key=`: its value redacted when
// the field is sensitive (`redact_log_value`), then capped (`cap_log_field_value`).
// Redaction runs first so a truncated value can never expose part of a secret,
// and a redacted value is already shorter than the cap. Every code path that
// renders structured fields into a log line goes through this one function.
[[nodiscard]] auto render_log_field_value(StructuredLogField const& field) -> std::string;
[[nodiscard]] auto structured_log_summary(StructuredLogEvent const& event) -> std::string;
[[nodiscard]] auto diagnostic_log_summary(std::string_view logger, std::string_view event,
                                          std::vector<StructuredLogField> fields) -> std::string;
[[nodiscard]] auto make_correlation_context(std::uint64_t sequence) -> CorrelationContext;
[[nodiscard]] auto current_correlation_context() noexcept -> CorrelationContext const*;
[[nodiscard]] auto with_correlation_fields(CorrelationContext const& context, std::vector<StructuredLogField> fields)
    -> std::vector<StructuredLogField>;
[[nodiscard]] auto logging_boundary_notes() -> std::vector<std::string>;
[[nodiscard]] auto metrics_are_safe(std::vector<MetricSample> const& metrics) noexcept -> bool;
[[nodiscard]] auto prometheus_metrics_summary(std::vector<MetricSample> const& metrics) -> std::string;
[[nodiscard]] auto health_snapshot_summary(HealthCheckSnapshot const& snapshot) -> std::string;
[[nodiscard]] auto hardening_observability_summary(platform::HardeningSelfCheck const& check)
    -> std::vector<std::string>;
[[nodiscard]] auto make_observability_snapshot(HealthCheckSnapshot health, std::vector<MetricSample> metrics,
                                               platform::HardeningSelfCheck const& hardening) -> ObservabilitySnapshot;
[[nodiscard]] auto observability_snapshot_is_safe(ObservabilitySnapshot const& snapshot) noexcept -> bool;

} // namespace merovingian::observability
