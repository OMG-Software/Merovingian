// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

// PHASE-B: forwarding includes, removed when consumers include the new headers directly.
#include "merovingian/config/AppserviceConfig.hpp"
#include "merovingian/config/ClientApiConfig.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/ConfigValidationFinding.hpp"
#include "merovingian/config/CorsConfig.hpp"
#include "merovingian/config/DatabaseBackend.hpp"
#include "merovingian/config/DatabaseConfig.hpp"
#include "merovingian/config/DatabaseRole.hpp"
#include "merovingian/config/DurationParseResult.hpp"
#include "merovingian/config/EmailConfig.hpp"
#include "merovingian/config/EncryptionSecurityConfig.hpp"
#include "merovingian/config/FederationBackfillConfig.hpp"
#include "merovingian/config/FederationQueryConfig.hpp"
#include "merovingian/config/FederationSecurityConfig.hpp"
#include "merovingian/config/FederationStateResolutionConfig.hpp"
#include "merovingian/config/FederationWorkerConfig.hpp"
#include "merovingian/config/HttpTransportConfig.hpp"
#include "merovingian/config/IdentityServerConfig.hpp"
#include "merovingian/config/ListenerConfig.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/LoggingSecurityConfig.hpp"
#include "merovingian/config/LoginThrottleSecurityConfig.hpp"
#include "merovingian/config/MediaSecurityConfig.hpp"
#include "merovingian/config/OidcConfig.hpp"
#include "merovingian/config/PasswordHashingConfig.hpp"
#include "merovingian/config/PasswordPolicyConfig.hpp"
#include "merovingian/config/PresenceConfig.hpp"
#include "merovingian/config/PushConfig.hpp"
#include "merovingian/config/RegistrationSecurityConfig.hpp"
#include "merovingian/config/SecretsSecurityConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/config/SizeLimitParseResult.hpp"
#include "merovingian/config/SsoConfig.hpp"
#include "merovingian/config/SsoIdentityProvider.hpp"
#include "merovingian/config/TrustSafetySecurityConfig.hpp"
#include "merovingian/config/TurnServerConfig.hpp"
#include "merovingian/http/rate_limit.hpp"
#include "merovingian/observability/logger.hpp"

#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

namespace merovingian::config
{

inline constexpr std::uint32_t min_audit_log_retention_days = 30U;
inline constexpr std::uint32_t max_audit_log_retention_days = 3650U;

class Config final
{
public:
    Config() = default;

    Config(ServerConfig server, ListenersConfig listeners, DatabaseConfig database, SecurityConfig security,
           ClientRateLimitsConfig client_rate_limits, LogModulesConfig log_modules,
           FederationWorkerConfig federation_worker = {}, AppserviceConfig appservice = {},
           PresenceConfig presence = {});

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
    [[nodiscard]] auto federation_worker() const noexcept -> FederationWorkerConfig const&;
    [[nodiscard]] auto federation_worker() noexcept -> FederationWorkerConfig&;
    [[nodiscard]] auto appservice() const noexcept -> AppserviceConfig const&;
    [[nodiscard]] auto appservice() noexcept -> AppserviceConfig&;
    [[nodiscard]] auto presence() const noexcept -> PresenceConfig const&;
    [[nodiscard]] auto presence() noexcept -> PresenceConfig&;

private:
    ServerConfig m_server{};
    ListenersConfig m_listeners{};
    DatabaseConfig m_database{};
    SecurityConfig m_security{};
    ClientRateLimitsConfig m_client_rate_limits{};
    LogModulesConfig m_log_modules{};
    FederationWorkerConfig m_federation_worker{};
    AppserviceConfig m_appservice{};
    PresenceConfig m_presence{};
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
[[nodiscard]] auto is_public_listener(ListenerConfig const& listener) noexcept -> bool;
[[nodiscard]] auto is_safe_cleartext_listener(ListenerConfig const& listener) noexcept -> bool;
[[nodiscard]] auto is_valid_public_baseurl(std::string_view public_baseurl) noexcept -> bool;
[[nodiscard]] auto is_valid_https_url(std::string_view url) noexcept -> bool;
[[nodiscard]] auto is_valid_https_origin_url(std::string_view url) noexcept -> bool;
[[nodiscard]] auto is_valid_federation_policy(std::string_view policy) noexcept -> bool;
[[nodiscard]] auto is_valid_media_acceptance_policy(std::string_view policy) noexcept -> bool;
[[nodiscard]] auto is_valid_federation_server_name(std::string_view server_name) noexcept -> bool;
[[nodiscard]] auto parse_size_limit(std::string_view value) noexcept -> SizeLimitParseResult;
[[nodiscard]] auto parse_duration_seconds(std::string_view value) noexcept -> DurationParseResult;
[[nodiscard]] auto is_private_or_loopback_range(std::string_view range) noexcept -> bool;
// True only for a CIDR with an explicit prefix, no host bits set, that lies
// wholly inside 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 or fc00::/7 (ADR-0231).
[[nodiscard]] auto private_ip_range_is_allowable(std::string_view range) noexcept -> bool;
[[nodiscard]] auto parse_rate_limit_policy(std::string_view value) noexcept -> std::optional<http::RateLimitPolicy>;
[[nodiscard]] auto parse_log_level(std::string_view value) noexcept -> std::optional<observability::LogLevel>;
[[nodiscard]] auto log_level_name(observability::LogLevel level) noexcept -> std::string_view;
[[nodiscard]] auto validate(Config const& config) -> std::vector<ConfigValidationFinding>;
[[nodiscard]] auto is_valid(Config const& config) -> bool;

} // namespace merovingian::config
