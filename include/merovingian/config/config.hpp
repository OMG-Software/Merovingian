// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/http/rate_limit.hpp"
#include "merovingian/observability/logger.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace merovingian::config
{

struct CorsConfig final
{
    // Origins to allow. Wildcard `*` is the default and means any origin is
    // allowed to make cross-origin requests. The CORS spec forbids combining
    // `*` with `allow_credentials=true`; the config parser enforces that.
    std::vector<std::string> allowed_origins{"*"};
    // How long the preflight result may be cached, in seconds.
    std::uint32_t max_age{86400U};
    // Whether to allow browser credentials (cookies, client TLS certs).
    // Matrix clients authenticate with bearer tokens so this is false by
    // default; flip it on only when you know what you are doing.
    bool allow_credentials{false};
    // Methods advertised in the preflight `Access-Control-Allow-Methods`
    // header. Empty string falls back to the standard list.
    std::string allow_methods{"GET, POST, PUT, DELETE, OPTIONS"};
    // Headers advertised in the preflight `Access-Control-Allow-Headers`
    // header. Empty string falls back to `authorization, content-type`,
    // which is the set Matrix clients actually use.
    std::string allow_headers{"authorization, content-type"};
};

struct ServerConfig final
{
    std::string server_name{"example.org"};
    std::string public_baseurl{"https://matrix.example.org"};
    std::vector<std::string> trusted_proxies{};
    // CORS preflight policy. Wildcard `*` is the default origin and is safe
    // for Matrix because clients authenticate with `Authorization: Bearer`
    // tokens, not browser-credentialed cookies. A `*` in `allowed_origins`
    // combined with `allow_credentials=true` is rejected at config-parse
    // time per the CORS spec.
    CorsConfig cors{};
};

struct ListenerConfig final
{
    std::string bind{};
    bool tls{false};
    std::string tls_certificate_file{};
    std::string tls_private_key_file{};
};

struct ListenersConfig final
{
    ListenerConfig client{"127.0.0.1:8008", false};
    ListenerConfig federation{"127.0.0.1:8009", false};
};

enum class DatabaseBackend
{
    postgresql,
    sqlite,
};

enum class DatabaseRole
{
    runtime,
    migration,
};

struct DatabaseConfig final
{
    std::string uri_file{"/etc/merovingian/db-uri"};
    std::uint32_t pool_size{16U};
    DatabaseBackend backend{DatabaseBackend::postgresql};
    DatabaseRole role{DatabaseRole::runtime};
    std::string sqlite_path{"/var/lib/merovingian/merovingian.sqlite3"};
};

struct RegistrationSecurityConfig final
{
    bool enabled{false};
    bool require_token{true};
    std::string token_file{};
};

struct EncryptionSecurityConfig final
{
    bool default_for_new_rooms{true};
    bool require_for_direct_messages{true};
    bool require_for_private_rooms{true};
    bool allow_unencrypted_public_rooms{true};
    bool block_unencrypted_federated_private_rooms{true};
};

struct FederationSecurityConfig final
{
    bool enabled{true};
    std::string default_policy{"allow"};
    std::vector<std::string> allowed_servers{};
    std::vector<std::string> denied_servers{};
    bool require_valid_tls{true};
    bool verify_json_signatures{true};
    std::vector<std::string> deny_ip_ranges{
        "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "::1/128", "fc00::/7",
    };
    std::string max_transaction_size{"10MiB"};
    std::string remote_timeout{"30s"};
};

struct MediaSecurityConfig final
{
    std::string max_upload_size{"50MiB"};
    bool quarantine_unknown_mime{true};
    bool enable_av_scanner{true};
    bool block_private_ip_fetches{true};
    std::string remote_fetch_timeout{"30s"};
    bool remote_fetch_enabled{false};
    bool decode_in_sandbox{true};
};

struct TrustSafetySecurityConfig final
{
    bool enabled{false};
    std::string policy_server_url{};
    std::string policy_server_timeout{"5s"};
    bool policy_server_allow_without_result{false};
};

struct LoggingSecurityConfig final
{
    bool redact_tokens{true};
    bool redact_event_content{true};
    bool structured{true};
};

// At-rest protection for high-value server secrets. The master key file
// contains raw secret material that is hashed with domain separation to
// derive the key used to encrypt the Ed25519 signing secret before it is
// written to the database. When empty, fresh signing keys cannot be created
// (legacy plaintext keys may still be loaded for migration).
struct SecretsSecurityConfig final
{
    std::string master_key_file{};
};

// Per-endpoint rate-limit policies. The values populate
// `http::RateLimitEngine` at `start_client_server()` time; restart
// required (see `src/config/reload_policy.cpp`). The 0.5.0 design doc
// (`docs/log-filtering-design.md`) lists the operator-agreed defaults:
// 20/min per IP for /login and /register, 5/min per user for /login,
// 30/min for keys/devices, 20/min for media, 120/min for federation,
// 90/min for everything else.
struct ClientRateLimitsConfig final
{
    std::unordered_map<std::string, http::RateLimitPolicy> per_ip{};
    std::unordered_map<std::string, http::RateLimitPolicy> per_user{};
    http::RateLimitPolicy default_per_ip{90U, 60U};
};

// Per-module log level overrides. Populated from `log_modules.<name>=<level>`
// keys in `merovingian.conf`. The wildcard key `*` sets the default for
// modules without an explicit entry (equivalent to
// `SingleLog::set_default_log_level`). Hot-reload is deliberately not
// supported in 0.5.0: log_modules affects startup-time bootstrap only
// and restart is required.
struct LogModulesConfig final
{
    std::unordered_map<std::string, observability::LogLevel> levels{};
};

struct SecurityConfig final
{
    RegistrationSecurityConfig registration{};
    EncryptionSecurityConfig encryption{};
    FederationSecurityConfig federation{};
    MediaSecurityConfig media{};
    TrustSafetySecurityConfig trust_safety{};
    LoggingSecurityConfig logging{};
    SecretsSecurityConfig secrets{};
    // Server-side token expiry, in milliseconds. 0 disables expiry for that
    // token kind (treated as no expiry). Defaults: access 1h, refresh 30d. The
    // advertised expires_in_ms reads from access_token_lifetime_ms so the
    // advertised TTL matches the enforced one.
    std::int64_t access_token_lifetime_ms{3600000};
    std::int64_t refresh_token_lifetime_ms{2592000000};
};

class Config final
{
public:
    Config() = default;

    Config(ServerConfig server, ListenersConfig listeners, DatabaseConfig database, SecurityConfig security,
           ClientRateLimitsConfig client_rate_limits, LogModulesConfig log_modules);

    [[nodiscard]] auto server() const noexcept -> ServerConfig const&;
    [[nodiscard]] auto server() noexcept -> ServerConfig&;
    [[nodiscard]] auto listeners() const noexcept -> ListenersConfig const&;
    [[nodiscard]] auto listeners() noexcept -> ListenersConfig&;
    [[nodiscard]] auto database() const noexcept -> DatabaseConfig const&;
    [[nodiscard]] auto database() noexcept -> DatabaseConfig&;
    [[nodiscard]] auto security() const noexcept -> SecurityConfig const&;
    [[nodiscard]] auto security() noexcept -> SecurityConfig&;
    [[nodiscard]] auto client_rate_limits() const noexcept -> ClientRateLimitsConfig const&;
    [[nodiscard]] auto client_rate_limits() noexcept -> ClientRateLimitsConfig&;
    [[nodiscard]] auto log_modules() const noexcept -> LogModulesConfig const&;
    [[nodiscard]] auto log_modules() noexcept -> LogModulesConfig&;

private:
    ServerConfig m_server{};
    ListenersConfig m_listeners{};
    DatabaseConfig m_database{};
    SecurityConfig m_security{};
    ClientRateLimitsConfig m_client_rate_limits{};
    LogModulesConfig m_log_modules{};
};

struct ConfigValidationFinding final
{
    std::string field{};
    std::string message{};
};

struct SizeLimitParseResult final
{
    bool valid{false};
    std::uint64_t bytes{0U};
};

struct DurationParseResult final
{
    bool valid{false};
    std::uint32_t seconds{0U};
};

[[nodiscard]] auto is_ascii_digit(char value) noexcept -> bool;
[[nodiscard]] auto starts_with(std::string_view value, std::string_view prefix) noexcept -> bool;
[[nodiscard]] auto database_backend_name(DatabaseBackend backend) noexcept -> std::string_view;
[[nodiscard]] auto parse_database_backend(std::string_view value) noexcept -> std::optional<DatabaseBackend>;
[[nodiscard]] auto database_backend_performance_warning(DatabaseBackend backend) noexcept -> std::string_view;
[[nodiscard]] auto database_role_name(DatabaseRole role) noexcept -> std::string_view;
[[nodiscard]] auto parse_database_role(std::string_view value) noexcept -> std::optional<DatabaseRole>;
[[nodiscard]] auto parse_port(std::string_view value) noexcept -> std::uint32_t;
[[nodiscard]] auto listener_host(std::string_view bind) noexcept -> std::string_view;
[[nodiscard]] auto is_loopback_host(std::string_view host) noexcept -> bool;
[[nodiscard]] auto is_valid_listener_bind(std::string_view bind) noexcept -> bool;
[[nodiscard]] auto is_safe_cleartext_listener(ListenerConfig const& listener) noexcept -> bool;
[[nodiscard]] auto is_valid_public_baseurl(std::string_view public_baseurl) noexcept -> bool;
[[nodiscard]] auto is_valid_federation_policy(std::string_view policy) noexcept -> bool;
[[nodiscard]] auto is_valid_federation_server_name(std::string_view server_name) noexcept -> bool;
[[nodiscard]] auto parse_size_limit(std::string_view value) noexcept -> SizeLimitParseResult;
[[nodiscard]] auto parse_duration_seconds(std::string_view value) noexcept -> DurationParseResult;
[[nodiscard]] auto is_private_or_loopback_range(std::string_view range) noexcept -> bool;
[[nodiscard]] auto parse_rate_limit_policy(std::string_view value) noexcept -> std::optional<http::RateLimitPolicy>;
[[nodiscard]] auto parse_log_level(std::string_view value) noexcept -> std::optional<observability::LogLevel>;
[[nodiscard]] auto log_level_name(observability::LogLevel level) noexcept -> std::string_view;
[[nodiscard]] auto validate(Config const& config) -> std::vector<ConfigValidationFinding>;
[[nodiscard]] auto is_valid(Config const& config) -> bool;

} // namespace merovingian::config
