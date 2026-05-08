// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>
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

} // namespace merovingian::config
