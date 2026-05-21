// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::config
{

struct ServerConfig final
{
    std::string server_name{"example.org"};
    std::string public_baseurl{"https://matrix.example.org"};
    std::vector<std::string> trusted_proxies{};
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

struct LoggingSecurityConfig final
{
    bool redact_tokens{true};
    bool redact_event_content{true};
    bool structured{true};
};

struct SecurityConfig final
{
    RegistrationSecurityConfig registration{};
    EncryptionSecurityConfig encryption{};
    FederationSecurityConfig federation{};
    MediaSecurityConfig media{};
    LoggingSecurityConfig logging{};
};

class Config final
{
public:
    Config() = default;

    Config(ServerConfig server, ListenersConfig listeners, DatabaseConfig database, SecurityConfig security);

    [[nodiscard]] auto server() const noexcept -> ServerConfig const&;
    [[nodiscard]] auto listeners() const noexcept -> ListenersConfig const&;
    [[nodiscard]] auto database() const noexcept -> DatabaseConfig const&;
    [[nodiscard]] auto security() const noexcept -> SecurityConfig const&;

private:
    ServerConfig m_server{};
    ListenersConfig m_listeners{};
    DatabaseConfig m_database{};
    SecurityConfig m_security{};
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
[[nodiscard]] auto validate(Config const& config) -> std::vector<ConfigValidationFinding>;
[[nodiscard]] auto is_valid(Config const& config) -> bool;

} // namespace merovingian::config
