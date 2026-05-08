// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
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
};

struct ListenersConfig final
{
    ListenerConfig client{"127.0.0.1:8008", false};
    ListenerConfig federation{"127.0.0.1:8448", false};
};

struct DatabaseConfig final
{
    std::string uri_file{"/etc/merovingian/db-uri"};
    std::uint32_t pool_size{16U};
};

struct RegistrationSecurityConfig final
{
    bool enabled{false};
    bool require_token{true};
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
    bool require_valid_tls{true};
    bool verify_json_signatures{true};
    std::vector<std::string> deny_ip_ranges{
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "::1/128",
        "fc00::/7",
    };
};

struct MediaSecurityConfig final
{
    std::string max_upload_size{"50MiB"};
    bool quarantine_unknown_mime{true};
    bool enable_av_scanner{true};
    bool block_private_ip_fetches{true};
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

    Config(
        ServerConfig server,
        ListenersConfig listeners,
        DatabaseConfig database,
        SecurityConfig security
    )
        : m_server{std::move(server)},
          m_listeners{std::move(listeners)},
          m_database{std::move(database)},
          m_security{std::move(security)}
    {
    }

    [[nodiscard]] auto server() const noexcept -> ServerConfig const&
    {
        return m_server;
    }

    [[nodiscard]] auto listeners() const noexcept -> ListenersConfig const&
    {
        return m_listeners;
    }

    [[nodiscard]] auto database() const noexcept -> DatabaseConfig const&
    {
        return m_database;
    }

    [[nodiscard]] auto security() const noexcept -> SecurityConfig const&
    {
        return m_security;
    }

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

[[nodiscard]] inline auto is_private_or_loopback_range(std::string_view range) noexcept -> bool
{
    return range == "127.0.0.0/8" || range == "10.0.0.0/8" || range == "172.16.0.0/12"
        || range == "192.168.0.0/16" || range == "::1/128" || range == "fc00::/7";
}

[[nodiscard]] inline auto validate(Config const& config) -> std::vector<ConfigValidationFinding>
{
    auto findings = std::vector<ConfigValidationFinding>{};

    if (config.server().server_name.empty())
    {
        findings.push_back({"server.server_name", "server name must not be empty"});
    }

    if (config.server().public_baseurl.empty())
    {
        findings.push_back({"server.public_baseurl", "public base URL must not be empty"});
    }

    if (config.listeners().client.bind.empty())
    {
        findings.push_back({"listeners.client.bind", "client listener bind address must not be empty"});
    }

    if (config.listeners().federation.bind.empty())
    {
        findings.push_back(
            {"listeners.federation.bind", "federation listener bind address must not be empty"}
        );
    }

    if (config.database().uri_file.empty())
    {
        findings.push_back({"database.uri_file", "database URI file must not be empty"});
    }

    if (config.database().pool_size == 0U)
    {
        findings.push_back({"database.pool_size", "database pool size must be greater than zero"});
    }

    if (config.security().registration.enabled && !config.security().registration.require_token)
    {
        findings.push_back(
            {"security.registration.require_token", "open registration requires token protection"}
        );
    }

    if (!config.security().encryption.default_for_new_rooms)
    {
        findings.push_back(
            {"security.encryption.default_for_new_rooms", "new rooms must default to encrypted"}
        );
    }

    if (!config.security().encryption.require_for_direct_messages)
    {
        findings.push_back(
            {"security.encryption.require_for_direct_messages", "direct messages must require encryption"}
        );
    }

    if (!config.security().federation.require_valid_tls)
    {
        findings.push_back({"security.federation.require_valid_tls", "federation TLS validation is required"});
    }

    if (!config.security().federation.verify_json_signatures)
    {
        findings.push_back(
            {"security.federation.verify_json_signatures", "federation JSON signatures must be verified"}
        );
    }

    auto has_private_or_loopback_block = false;
    for (auto const& range : config.security().federation.deny_ip_ranges)
    {
        has_private_or_loopback_block = has_private_or_loopback_block || is_private_or_loopback_range(range);
    }

    if (!has_private_or_loopback_block)
    {
        findings.push_back(
            {"security.federation.deny_ip_ranges", "federation must block private or loopback ranges"}
        );
    }

    if (!config.security().media.block_private_ip_fetches)
    {
        findings.push_back({"security.media.block_private_ip_fetches", "remote media fetches must block private IPs"});
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
        findings.push_back(
            {"security.logging.redact_event_content", "event content must be redacted from logs"}
        );
    }

    return findings;
}

[[nodiscard]] inline auto is_valid(Config const& config) -> bool
{
    return validate(config).empty();
}

} // namespace merovingian::config
