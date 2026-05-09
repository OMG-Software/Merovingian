// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/config/config.hpp>

#include <limits>
#include <utility>

namespace merovingian::config
{

Config::Config(
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

auto Config::server() const noexcept -> ServerConfig const&
{
    return m_server;
}

auto Config::listeners() const noexcept -> ListenersConfig const&
{
    return m_listeners;
}

auto Config::database() const noexcept -> DatabaseConfig const&
{
    return m_database;
}

auto Config::security() const noexcept -> SecurityConfig const&
{
    return m_security;
}

auto is_ascii_digit(char value) noexcept -> bool
{
    return value >= '0' && value <= '9';
}

auto starts_with(std::string_view value, std::string_view prefix) noexcept -> bool
{
    return value.size() >= prefix.size() && value.substr(0U, prefix.size()) == prefix;
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

    auto multiplier = std::uint64_t{1U};
    auto const suffix = value.substr(index);
    if (suffix.empty() || suffix == "B")
    {
        multiplier = 1U;
    }
    else if (suffix == "KiB")
    {
        multiplier = 1024U;
    }
    else if (suffix == "MiB")
    {
        multiplier = 1024U * 1024U;
    }
    else if (suffix == "GiB")
    {
        multiplier = 1024U * 1024U * 1024U;
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

auto is_private_or_loopback_range(std::string_view range) noexcept -> bool
{
    return range == "127.0.0.0/8" || range == "10.0.0.0/8" || range == "172.16.0.0/12"
        || range == "192.168.0.0/16" || range == "::1/128" || range == "fc00::/7";
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

    if (!is_valid_listener_bind(config.listeners().client.bind))
    {
        findings.push_back({"listeners.client.bind", "client listener bind address must be host:port"});
    }
    else if (!is_safe_cleartext_listener(config.listeners().client))
    {
        findings.push_back(
            {"listeners.client.tls", "cleartext client listener must bind only to loopback"}
        );
    }

    if (!is_valid_listener_bind(config.listeners().federation.bind))
    {
        findings.push_back({"listeners.federation.bind", "federation listener bind address must be host:port"});
    }
    else if (!is_safe_cleartext_listener(config.listeners().federation))
    {
        findings.push_back(
            {"listeners.federation.tls", "cleartext federation listener must bind only to loopback"}
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

    if (!is_valid_federation_policy(config.security().federation.default_policy))
    {
        findings.push_back(
            {"security.federation.default_policy", "federation default policy must be allow or deny"}
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

    auto const media_max_upload_size = parse_size_limit(config.security().media.max_upload_size);
    if (!media_max_upload_size.valid)
    {
        findings.push_back(
            {"security.media.max_upload_size", "media upload size must be a positive bounded byte size"}
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

auto is_valid(Config const& config) -> bool
{
    return validate(config).empty();
}

} // namespace merovingian::config
