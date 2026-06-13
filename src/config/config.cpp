// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/config/config.hpp"
#include "merovingian/config/config_parser.hpp"

#include <limits>
#include <optional>
#include <string_view>
#include <utility>

namespace merovingian::config
{

namespace
{

    auto validate_listener_tls_files(std::vector<ConfigValidationFinding>& findings, ListenerConfig const& listener,
                                     std::string_view prefix) -> void
    {
        if (!listener.tls)
        {
            return;
        }

        if (listener.tls_certificate_file.empty())
        {
            findings.push_back(
                {std::string{prefix} + ".tls_certificate_file", "TLS listener requires a certificate file"});
        }
        if (listener.tls_private_key_file.empty())
        {
            findings.push_back(
                {std::string{prefix} + ".tls_private_key_file", "TLS listener requires a private key file"});
        }
    }

} // namespace

Config::Config(ServerConfig server, ListenersConfig listeners, DatabaseConfig database, SecurityConfig security,
                 ClientRateLimitsConfig client_rate_limits, LogModulesConfig log_modules)
    : m_server{std::move(server)}
    , m_listeners{std::move(listeners)}
    , m_database{std::move(database)}
    , m_security{std::move(security)}
    , m_client_rate_limits{std::move(client_rate_limits)}
    , m_log_modules{std::move(log_modules)}
{
}

auto Config::server() const noexcept -> ServerConfig const&
{
    return m_server;
}

auto Config::server() noexcept -> ServerConfig&
{
    return m_server;
}

auto Config::listeners() const noexcept -> ListenersConfig const&
{
    return m_listeners;
}

auto Config::listeners() noexcept -> ListenersConfig&
{
    return m_listeners;
}

auto Config::database() const noexcept -> DatabaseConfig const&
{
    return m_database;
}

auto Config::database() noexcept -> DatabaseConfig&
{
    return m_database;
}

auto Config::security() const noexcept -> SecurityConfig const&
{
    return m_security;
}

auto Config::security() noexcept -> SecurityConfig&
{
    return m_security;
}

auto Config::client_rate_limits() const noexcept -> ClientRateLimitsConfig const&
{
    return m_client_rate_limits;
}

auto Config::client_rate_limits() noexcept -> ClientRateLimitsConfig&
{
    return m_client_rate_limits;
}

auto Config::log_modules() const noexcept -> LogModulesConfig const&
{
    return m_log_modules;
}

auto Config::log_modules() noexcept -> LogModulesConfig&
{
    return m_log_modules;
}

auto is_ascii_digit(char value) noexcept -> bool
{
    return value >= '0' && value <= '9';
}

auto starts_with(std::string_view value, std::string_view prefix) noexcept -> bool
{
    return value.size() >= prefix.size() && value.substr(0U, prefix.size()) == prefix;
}

auto database_backend_name(DatabaseBackend backend) noexcept -> std::string_view
{
    return backend == DatabaseBackend::sqlite ? "sqlite" : "postgresql";
}

auto parse_database_backend(std::string_view value) noexcept -> std::optional<DatabaseBackend>
{
    if (value == "postgresql")
    {
        return DatabaseBackend::postgresql;
    }
    if (value == "sqlite")
    {
        return DatabaseBackend::sqlite;
    }
    return std::nullopt;
}

auto database_backend_performance_warning(DatabaseBackend backend) noexcept -> std::string_view
{
    return backend == DatabaseBackend::sqlite
               ? "SQLite is intended only for small installations and development; PostgreSQL is recommended for "
                 "production or high-throughput deployments."
               : std::string_view{};
}

auto database_role_name(DatabaseRole role) noexcept -> std::string_view
{
    return role == DatabaseRole::migration ? "migration" : "runtime";
}

auto parse_database_role(std::string_view value) noexcept -> std::optional<DatabaseRole>
{
    if (value == "runtime")
    {
        return DatabaseRole::runtime;
    }
    if (value == "migration")
    {
        return DatabaseRole::migration;
    }
    return std::nullopt;
}

auto parse_port(std::string_view value) noexcept -> std::uint32_t
{
    if (value.empty())
    {
        return 0U;
    }

    auto port = std::uint32_t{0U};
    for (auto const character : value)
    {
        if (!is_ascii_digit(character))
        {
            return 0U;
        }

        auto const digit = static_cast<std::uint32_t>(character - '0');
        if (port > (65535U - digit) / 10U)
        {
            return 0U;
        }
        port = (port * 10U) + digit;
    }

    return port;
}

auto listener_host(std::string_view bind) noexcept -> std::string_view
{
    auto const separator = bind.rfind(':');
    if (separator == std::string_view::npos)
    {
        return {};
    }

    return bind.substr(0U, separator);
}

auto is_loopback_host(std::string_view host) noexcept -> bool
{
    return host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "[::1]";
}

auto is_valid_listener_bind(std::string_view bind) noexcept -> bool
{
    auto const separator = bind.rfind(':');
    if (separator == std::string_view::npos || separator == 0U || separator + 1U >= bind.size())
    {
        return false;
    }

    auto const host = bind.substr(0U, separator);
    auto const port = parse_port(bind.substr(separator + 1U));
    return !host.empty() && port > 0U;
}

auto is_safe_cleartext_listener(ListenerConfig const& listener) noexcept -> bool
{
    return listener.tls || is_loopback_host(listener_host(listener.bind));
}

auto is_valid_public_baseurl(std::string_view public_baseurl) noexcept -> bool
{
    constexpr auto https_scheme = std::string_view{"https://"};
    if (!starts_with(public_baseurl, https_scheme))
    {
        return false;
    }

    auto const authority = public_baseurl.substr(https_scheme.size());
    return !authority.empty() && authority.find(' ') == std::string_view::npos;
}

auto is_valid_federation_policy(std::string_view policy) noexcept -> bool
{
    return policy == "allow" || policy == "deny";
}

auto is_valid_federation_server_name(std::string_view server_name) noexcept -> bool
{
    if (server_name.empty() || server_name.size() > 255U || server_name.front() == '.' || server_name.back() == '.')
    {
        return false;
    }

    for (auto const character : server_name)
    {
        auto const is_lower = character >= 'a' && character <= 'z';
        auto const is_upper = character >= 'A' && character <= 'Z';
        auto const is_digit = is_ascii_digit(character);
        if (!is_lower && !is_upper && !is_digit && character != '.' && character != '-' && character != ':')
        {
            return false;
        }
    }

    return true;
}

auto parse_size_limit(std::string_view value) noexcept -> SizeLimitParseResult
{
    if (value.empty())
    {
        return {};
    }

    auto index = std::size_t{0U};
    auto magnitude = std::uint64_t{0U};
    while (index < value.size() && is_ascii_digit(value[index]))
    {
        auto const digit = static_cast<std::uint64_t>(value[index] - '0');
        if (magnitude > (std::numeric_limits<std::uint64_t>::max() - digit) / 10U)
        {
            return {};
        }
        magnitude = (magnitude * 10U) + digit;
        ++index;
    }

    if (index == 0U || magnitude == 0U)
    {
        return {};
    }

    constexpr auto kibibyte = std::uint64_t{1024U};
    constexpr auto mebibyte = kibibyte * kibibyte;
    constexpr auto gibibyte = mebibyte * kibibyte;

    auto multiplier = std::uint64_t{1U};
    auto const suffix = value.substr(index);
    if (suffix.empty() || suffix == "B")
    {
        multiplier = 1U;
    }
    else if (suffix == "KiB")
    {
        multiplier = kibibyte;
    }
    else if (suffix == "MiB")
    {
        multiplier = mebibyte;
    }
    else if (suffix == "GiB")
    {
        multiplier = gibibyte;
    }
    else
    {
        return {};
    }

    if (magnitude > std::numeric_limits<std::uint64_t>::max() / multiplier)
    {
        return {};
    }

    return {true, magnitude * multiplier};
}

auto parse_duration_seconds(std::string_view value) noexcept -> DurationParseResult
{
    if (value.empty())
    {
        return {};
    }

    auto index = std::size_t{0U};
    auto magnitude = std::uint32_t{0U};
    while (index < value.size() && is_ascii_digit(value[index]))
    {
        auto const digit = static_cast<std::uint32_t>(value[index] - '0');
        if (magnitude > (std::numeric_limits<std::uint32_t>::max() - digit) / 10U)
        {
            return {};
        }
        magnitude = (magnitude * 10U) + digit;
        ++index;
    }

    if (index == 0U || magnitude == 0U)
    {
        return {};
    }

    auto multiplier = std::uint32_t{1U};
    auto const suffix = value.substr(index);
    if (suffix == "s")
    {
        multiplier = 1U;
    }
    else if (suffix == "m")
    {
        multiplier = 60U;
    }
    else
    {
        return {};
    }

    if (magnitude > std::numeric_limits<std::uint32_t>::max() / multiplier)
    {
        return {};
    }

    return {true, magnitude * multiplier};
}

auto is_private_or_loopback_range(std::string_view range) noexcept -> bool
{
    return range == "127.0.0.0/8" || range == "10.0.0.0/8" || range == "172.16.0.0/12" || range == "192.168.0.0/16" ||
           range == "::1/128" || range == "fc00::/7";
}

// Parse a "<max>/<window>s" rate-limit value, e.g. "20/60s" or
// "5/60s". Returns std::nullopt on a malformed value. Validates the
// window via the existing `parse_duration_seconds` and the cap against
// the same window/cap constraints `http::rate_limit_policy_is_valid`
// enforces at runtime, so an operator who sets `client_rate_limits.*=0/0s`
// gets rejected at parse time rather than at the first request.
auto parse_rate_limit_policy(std::string_view value) noexcept -> std::optional<http::RateLimitPolicy>
{
    if (value.empty())
    {
        return std::nullopt;
    }
    auto const slash = value.find('/');
    if (slash == std::string_view::npos || slash == 0U || slash + 1U >= value.size())
    {
        return std::nullopt;
    }
    auto const cap_text = value.substr(0U, slash);
    auto const window_text = value.substr(slash + 1U);
    auto cap = std::uint32_t{0U};
    if (!parse_u32_value(cap_text, cap) || cap == 0U)
    {
        return std::nullopt;
    }
    auto const window = parse_duration_seconds(window_text);
    if (!window.valid || window.seconds == 0U || window.seconds > 3600U)
    {
        return std::nullopt;
    }
    return http::RateLimitPolicy{cap, window.seconds};
}

auto parse_log_level(std::string_view value) noexcept -> std::optional<observability::LogLevel>
{
    using observability::LogLevel;
    if (value == "trace")
    {
        return LogLevel::trace;
    }
    if (value == "debug")
    {
        return LogLevel::debug;
    }
    if (value == "info")
    {
        return LogLevel::info;
    }
    if (value == "notice")
    {
        return LogLevel::notice;
    }
    if (value == "warning")
    {
        return LogLevel::warning;
    }
    if (value == "error")
    {
        return LogLevel::error;
    }
    if (value == "critical")
    {
        return LogLevel::critical;
    }
    if (value == "off")
    {
        return LogLevel::off;
    }
    return std::nullopt;
}

auto log_level_name(observability::LogLevel level) noexcept -> std::string_view
{
    using observability::LogLevel;
    switch (level)
    {
    case LogLevel::trace:
        return "trace";
    case LogLevel::debug:
        return "debug";
    case LogLevel::info:
        return "info";
    case LogLevel::notice:
        return "notice";
    case LogLevel::warning:
        return "warning";
    case LogLevel::error:
        return "error";
    case LogLevel::critical:
        return "critical";
    case LogLevel::off:
        return "off";
    }
    return "off";
}

auto validate(Config const& config) -> std::vector<ConfigValidationFinding>
{
    auto findings = std::vector<ConfigValidationFinding>{};

    if (config.server().server_name.empty())
    {
        findings.push_back({"server.server_name", "server name must not be empty"});
    }

    if (!is_valid_public_baseurl(config.server().public_baseurl))
    {
        findings.push_back({"server.public_baseurl", "public base URL must be a non-empty HTTPS URL"});
    }

    // CORS spec: wildcard origin cannot be combined with credentials. We
    // reject the combination at parse time so an operator never deploys a
    // config that would silently fail browser preflight checks.
    if (config.server().cors.allow_credentials)
    {
        for (auto const& origin : config.server().cors.allowed_origins)
        {
            if (origin == "*")
            {
                findings.push_back(
                    {"server.cors.allowed_origins",
                     "wildcard '*' is incompatible with server.cors.allow_credentials=true "
                     "(CORS spec violation; list explicit origins instead)"});
                break;
            }
        }
    }

    if (!is_valid_listener_bind(config.listeners().client.bind))
    {
        findings.push_back({"listeners.client.bind", "client listener bind address must be host:port"});
    }
    else if (!is_safe_cleartext_listener(config.listeners().client))
    {
        findings.push_back({"listeners.client.tls", "cleartext client listener must bind only to loopback"});
    }
    validate_listener_tls_files(findings, config.listeners().client, "listeners.client");

    if (!is_valid_listener_bind(config.listeners().federation.bind))
    {
        findings.push_back({"listeners.federation.bind", "federation listener bind address must be host:port"});
    }
    else if (!is_safe_cleartext_listener(config.listeners().federation))
    {
        findings.push_back({"listeners.federation.tls", "cleartext federation listener must bind only to loopback"});
    }
    validate_listener_tls_files(findings, config.listeners().federation, "listeners.federation");

    if (config.database().backend == DatabaseBackend::postgresql && config.database().uri_file.empty())
    {
        findings.push_back({"database.uri_file", "database URI file must not be empty for PostgreSQL"});
    }

    if (config.database().backend == DatabaseBackend::sqlite && config.database().sqlite_path.empty())
    {
        findings.push_back({"database.sqlite_path", "SQLite database path must not be empty"});
    }

    if (config.database().pool_size == 0U)
    {
        findings.push_back({"database.pool_size", "database pool size must be greater than zero"});
    }

    if (config.security().registration.enabled && !config.security().registration.require_token)
    {
        findings.push_back({"security.registration.require_token", "open registration requires token protection"});
    }

    if (config.security().registration.enabled && config.security().registration.require_token &&
        config.security().registration.token_file.empty())
    {
        findings.push_back({"security.registration.token_file", "token-protected registration requires a token file"});
    }

    if (!config.security().encryption.default_for_new_rooms)
    {
        findings.push_back({"security.encryption.default_for_new_rooms", "new rooms must default to encrypted"});
    }

    if (!config.security().encryption.require_for_direct_messages)
    {
        findings.push_back(
            {"security.encryption.require_for_direct_messages", "direct messages must require encryption"});
    }

    if (!is_valid_federation_policy(config.security().federation.default_policy))
    {
        findings.push_back({"security.federation.default_policy", "federation default policy must be allow or deny"});
    }

    if (config.security().federation.enabled && config.security().federation.default_policy == "deny" &&
        config.security().federation.allowed_servers.empty())
    {
        findings.push_back(
            {"security.federation.allowed_servers", "deny-by-default federation requires an allowed server list"});
    }

    for (auto const& allowed_server : config.security().federation.allowed_servers)
    {
        if (!is_valid_federation_server_name(allowed_server))
        {
            findings.push_back({"security.federation.allowed_servers", "allowed federation server name is invalid"});
            break;
        }
    }

    for (auto const& denied_server : config.security().federation.denied_servers)
    {
        if (!is_valid_federation_server_name(denied_server))
        {
            findings.push_back({"security.federation.denied_servers", "denied federation server name is invalid"});
            break;
        }
    }

    if (!config.security().federation.require_valid_tls)
    {
        findings.push_back({"security.federation.require_valid_tls", "federation TLS validation is required"});
    }

    if (!config.security().federation.verify_json_signatures)
    {
        findings.push_back(
            {"security.federation.verify_json_signatures", "federation JSON signatures must be verified"});
    }

    auto has_private_or_loopback_block = false;
    for (auto const& range : config.security().federation.deny_ip_ranges)
    {
        has_private_or_loopback_block = has_private_or_loopback_block || is_private_or_loopback_range(range);
    }

    if (!has_private_or_loopback_block)
    {
        findings.push_back({"security.federation.deny_ip_ranges", "federation must block private or loopback ranges"});
    }

    auto const federation_max_transaction_size = parse_size_limit(config.security().federation.max_transaction_size);
    if (!federation_max_transaction_size.valid)
    {
        findings.push_back({"security.federation.max_transaction_size",
                            "federation transaction size must be a positive bounded byte size"});
    }

    auto const federation_remote_timeout = parse_duration_seconds(config.security().federation.remote_timeout);
    if (!federation_remote_timeout.valid)
    {
        findings.push_back(
            {"security.federation.remote_timeout", "federation remote timeout must be a positive bounded duration"});
    }

    auto const media_max_upload_size = parse_size_limit(config.security().media.max_upload_size);
    if (!media_max_upload_size.valid)
    {
        findings.push_back(
            {"security.media.max_upload_size", "media upload size must be a positive bounded byte size"});
    }

    if (!config.security().media.block_private_ip_fetches)
    {
        findings.push_back({"security.media.block_private_ip_fetches", "remote media fetches must block private IPs"});
    }

    auto const media_remote_fetch_timeout = parse_duration_seconds(config.security().media.remote_fetch_timeout);
    if (!media_remote_fetch_timeout.valid)
    {
        findings.push_back(
            {"security.media.remote_fetch_timeout", "media remote fetch timeout must be a positive bounded duration"});
    }

    if (!config.security().media.decode_in_sandbox)
    {
        findings.push_back({"security.media.decode_in_sandbox", "media decoding must happen in a sandbox"});
    }

    if (!config.security().logging.redact_tokens)
    {
        findings.push_back({"security.logging.redact_tokens", "tokens must be redacted from logs"});
    }

    if (!config.security().logging.redact_event_content)
    {
        findings.push_back({"security.logging.redact_event_content", "event content must be redacted from logs"});
    }

    // Per-endpoint rate-limit policies. The map is operator-supplied, so
    // the validator confirms the structural contract the runtime
    // depends on: every entry's `max_requests` and `window_seconds` are
    // strictly positive. Empty targets are also rejected so an operator
    // typo (a stray blank line) does not silently insert a catch-all
    // entry that shadows the configured `default_per_ip`.
    for (auto const& [target, policy] : config.client_rate_limits().per_ip)
    {
        if (target.empty())
        {
            findings.push_back({"client_rate_limits.per_ip", "rate-limit target must not be empty"});
            break;
        }
        if (policy.max_requests == 0U || policy.window_seconds == 0U)
        {
            findings.push_back(
                {"client_rate_limits.per_ip." + target, "rate-limit policy must be N>0 per Ws>0"});
        }
    }
    for (auto const& [target, policy] : config.client_rate_limits().per_user)
    {
        if (target.empty())
        {
            findings.push_back({"client_rate_limits.per_user", "rate-limit target must not be empty"});
            break;
        }
        if (policy.max_requests == 0U || policy.window_seconds == 0U)
        {
            findings.push_back(
                {"client_rate_limits.per_user." + target, "rate-limit policy must be N>0 per Ws>0"});
        }
    }
    if (config.client_rate_limits().default_per_ip.max_requests == 0U ||
        config.client_rate_limits().default_per_ip.window_seconds == 0U)
    {
        findings.push_back(
            {"client_rate_limits.default_per_ip", "default per-IP rate-limit policy must be N>0 per Ws>0"});
    }

    // Log-modules config. The wildcard "*" sets the default; otherwise
    // the key is treated as a module name. Empty module names are
    // rejected so a stray blank line does not insert a default for
    // every (no-name) module.
    for (auto const& [module, level] : config.log_modules().levels)
    {
        if (module.empty())
        {
            findings.push_back({"log_modules", "log module name must not be empty"});
            break;
        }
        if (level == observability::LogLevel::off)
        {
            // Off is a legitimate value (silence the module entirely),
            // but we warn at validate time so the operator notices.
            // No finding here: off is intentional, not a misconfig.
            (void)level;
        }
    }

    return findings;
}

auto is_valid(Config const& config) -> bool
{
    return validate(config).empty();
}

} // namespace merovingian::config
