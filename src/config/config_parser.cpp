// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/config/config_parser.hpp"

#include <limits>
#include <string>
#include <utility>

namespace merovingian::config
{

namespace
{

    [[nodiscard]] auto contains_key(std::vector<std::string> const& keys, std::string_view key) noexcept -> bool
    {
        for (auto const& existing : keys)
        {
            if (existing == key)
            {
                return true;
            }
        }

        return false;
    }

    inline auto add_parse_finding(std::vector<ConfigValidationFinding>& findings, std::string field,
                                  std::string message) -> void
    {
        findings.push_back({std::move(field), std::move(message)});
    }

    inline auto apply_config_value(ServerConfig& server, ListenersConfig& listeners, DatabaseConfig& database,
                                   SecurityConfig& security, std::string_view key, std::string_view value,
                                   std::vector<ConfigValidationFinding>& findings) -> void
    {
        if (key == "server.name")
        {
            server.server_name = std::string{value};
        }
        else if (key == "server.public_baseurl")
        {
            server.public_baseurl = std::string{value};
        }
        else if (key == "server.trusted_proxies")
        {
            server.trusted_proxies = parse_string_list(value);
        }
        else if (key == "listeners.client.bind")
        {
            listeners.client.bind = std::string{value};
        }
        else if (key == "listeners.client.tls")
        {
            if (!parse_bool_value(value, listeners.client.tls))
            {
                add_parse_finding(findings, std::string{key}, "expected boolean value");
            }
        }
        else if (key == "listeners.client.tls_certificate_file")
        {
            listeners.client.tls_certificate_file = std::string{value};
        }
        else if (key == "listeners.client.tls_private_key_file")
        {
            listeners.client.tls_private_key_file = std::string{value};
        }
        else if (key == "listeners.federation.bind")
        {
            listeners.federation.bind = std::string{value};
        }
        else if (key == "listeners.federation.tls")
        {
            if (!parse_bool_value(value, listeners.federation.tls))
            {
                add_parse_finding(findings, std::string{key}, "expected boolean value");
            }
        }
        else if (key == "listeners.federation.tls_certificate_file")
        {
            listeners.federation.tls_certificate_file = std::string{value};
        }
        else if (key == "listeners.federation.tls_private_key_file")
        {
            listeners.federation.tls_private_key_file = std::string{value};
        }
        else if (key == "database.backend")
        {
            auto const backend = parse_database_backend(value);
            if (backend.has_value())
            {
                database.backend = *backend;
            }
            else
            {
                add_parse_finding(findings, std::string{key}, "expected database backend postgresql or sqlite");
            }
        }
        else if (key == "database.uri_file")
        {
            database.uri_file = std::string{value};
        }
        else if (key == "database.sqlite_path")
        {
            database.sqlite_path = std::string{value};
        }
        else if (key == "database.pool_size")
        {
            if (!parse_u32_value(value, database.pool_size))
            {
                add_parse_finding(findings, std::string{key}, "expected unsigned integer value");
            }
        }
        else if (key == "security.registration.enabled")
        {
            if (!parse_bool_value(value, security.registration.enabled))
            {
                add_parse_finding(findings, std::string{key}, "expected boolean value");
            }
        }
        else if (key == "security.registration.require_token")
        {
            if (!parse_bool_value(value, security.registration.require_token))
            {
                add_parse_finding(findings, std::string{key}, "expected boolean value");
            }
        }
        else if (key == "security.encryption.default_for_new_rooms")
        {
            if (!parse_bool_value(value, security.encryption.default_for_new_rooms))
            {
                add_parse_finding(findings, std::string{key}, "expected boolean value");
            }
        }
        else if (key == "security.encryption.require_for_direct_messages")
        {
            if (!parse_bool_value(value, security.encryption.require_for_direct_messages))
            {
                add_parse_finding(findings, std::string{key}, "expected boolean value");
            }
        }
        else if (key == "security.encryption.require_for_private_rooms")
        {
            if (!parse_bool_value(value, security.encryption.require_for_private_rooms))
            {
                add_parse_finding(findings, std::string{key}, "expected boolean value");
            }
        }
        else if (key == "security.encryption.allow_unencrypted_public_rooms")
        {
            if (!parse_bool_value(value, security.encryption.allow_unencrypted_public_rooms))
            {
                add_parse_finding(findings, std::string{key}, "expected boolean value");
            }
        }
        else if (key == "security.encryption.block_unencrypted_federated_private_rooms")
        {
            if (!parse_bool_value(value, security.encryption.block_unencrypted_federated_private_rooms))
            {
                add_parse_finding(findings, std::string{key}, "expected boolean value");
            }
        }
        else if (key == "security.federation.enabled")
        {
            if (!parse_bool_value(value, security.federation.enabled))
            {
                add_parse_finding(findings, std::string{key}, "expected boolean value");
            }
        }
        else if (key == "security.federation.default_policy")
        {
            security.federation.default_policy = std::string{value};
        }
        else if (key == "security.federation.allowed_servers")
        {
            security.federation.allowed_servers = parse_string_list(value);
        }
        else if (key == "security.federation.denied_servers")
        {
            security.federation.denied_servers = parse_string_list(value);
        }
        else if (key == "security.federation.require_valid_tls")
        {
            if (!parse_bool_value(value, security.federation.require_valid_tls))
            {
                add_parse_finding(findings, std::string{key}, "expected boolean value");
            }
        }
        else if (key == "security.federation.verify_json_signatures")
        {
            if (!parse_bool_value(value, security.federation.verify_json_signatures))
            {
                add_parse_finding(findings, std::string{key}, "expected boolean value");
            }
        }
        else if (key == "security.federation.deny_ip_ranges")
        {
            security.federation.deny_ip_ranges = parse_string_list(value);
        }
        else if (key == "security.federation.max_transaction_size")
        {
            security.federation.max_transaction_size = std::string{value};
        }
        else if (key == "security.federation.remote_timeout")
        {
            security.federation.remote_timeout = std::string{value};
        }
        else if (key == "security.media.max_upload_size")
        {
            security.media.max_upload_size = std::string{value};
        }
        else if (key == "security.media.quarantine_unknown_mime")
        {
            if (!parse_bool_value(value, security.media.quarantine_unknown_mime))
            {
                add_parse_finding(findings, std::string{key}, "expected boolean value");
            }
        }
        else if (key == "security.media.enable_av_scanner")
        {
            if (!parse_bool_value(value, security.media.enable_av_scanner))
            {
                add_parse_finding(findings, std::string{key}, "expected boolean value");
            }
        }
        else if (key == "security.media.block_private_ip_fetches")
        {
            if (!parse_bool_value(value, security.media.block_private_ip_fetches))
            {
                add_parse_finding(findings, std::string{key}, "expected boolean value");
            }
        }
        else if (key == "security.media.remote_fetch_timeout")
        {
            security.media.remote_fetch_timeout = std::string{value};
        }
        else if (key == "security.media.decode_in_sandbox")
        {
            if (!parse_bool_value(value, security.media.decode_in_sandbox))
            {
                add_parse_finding(findings, std::string{key}, "expected boolean value");
            }
        }
        else if (key == "security.logging.redact_tokens")
        {
            if (!parse_bool_value(value, security.logging.redact_tokens))
            {
                add_parse_finding(findings, std::string{key}, "expected boolean value");
            }
        }
        else if (key == "security.logging.redact_event_content")
        {
            if (!parse_bool_value(value, security.logging.redact_event_content))
            {
                add_parse_finding(findings, std::string{key}, "expected boolean value");
            }
        }
        else if (key == "security.logging.structured")
        {
            if (!parse_bool_value(value, security.logging.structured))
            {
                add_parse_finding(findings, std::string{key}, "expected boolean value");
            }
        }
        else
        {
            add_parse_finding(findings, std::string{key}, "unknown configuration key");
        }
    }

} // namespace

auto trim_ascii(std::string_view value) noexcept -> std::string_view
{
    auto begin = std::size_t{0U};
    auto end = value.size();

    while (begin < end && (value[begin] == ' ' || value[begin] == '\t' || value[begin] == '\r'))
    {
        ++begin;
    }

    while (end > begin && (value[end - 1U] == ' ' || value[end - 1U] == '\t' || value[end - 1U] == '\r'))
    {
        --end;
    }

    return value.substr(begin, end - begin);
}

auto parse_bool_value(std::string_view value, bool& output) noexcept -> bool
{
    if (value == "true")
    {
        output = true;
        return true;
    }

    if (value == "false")
    {
        output = false;
        return true;
    }

    return false;
}

auto parse_u32_value(std::string_view value, std::uint32_t& output) noexcept -> bool
{
    if (value.empty())
    {
        return false;
    }

    auto parsed = std::uint32_t{0U};
    for (auto const character : value)
    {
        if (!is_ascii_digit(character))
        {
            return false;
        }

        auto const digit = static_cast<std::uint32_t>(character - '0');
        if (parsed > (std::numeric_limits<std::uint32_t>::max() - digit) / 10U)
        {
            return false;
        }
        parsed = (parsed * 10U) + digit;
    }

    output = parsed;
    return true;
}

auto parse_string_list(std::string_view value) -> std::vector<std::string>
{
    auto result = std::vector<std::string>{};
    auto remaining = value;

    while (!remaining.empty())
    {
        auto const separator = remaining.find(',');
        auto const item = trim_ascii(remaining.substr(0U, separator));
        if (!item.empty())
        {
            result.emplace_back(item);
        }

        if (separator == std::string_view::npos)
        {
            break;
        }

        remaining = remaining.substr(separator + 1U);
    }

    return result;
}

auto parse_key_value_config(std::string_view input) -> ConfigParseResult
{
    auto server = ServerConfig{};
    auto listeners = ListenersConfig{};
    auto database = DatabaseConfig{};
    auto security = SecurityConfig{};
    auto findings = std::vector<ConfigValidationFinding>{};
    auto seen_keys = std::vector<std::string>{};

    if (input.size() > max_config_bytes)
    {
        add_parse_finding(findings, "config", "configuration file is too large");
        return {Config{}, findings};
    }

    auto line_number = std::uint32_t{1U};
    while (!input.empty())
    {
        auto const newline = input.find('\n');
        auto const raw_line = input.substr(0U, newline);
        auto const line = trim_ascii(raw_line);

        if (raw_line.size() > max_config_line_bytes)
        {
            add_parse_finding(findings, "line " + std::to_string(line_number), "line is too long");
        }
        else if (!line.empty() && line[0] != '#')
        {
            auto const separator = line.find('=');
            if (separator == std::string_view::npos || separator == 0U)
            {
                add_parse_finding(findings, "line " + std::to_string(line_number), "expected key=value");
            }
            else
            {
                auto const key = trim_ascii(line.substr(0U, separator));
                auto const value = trim_ascii(line.substr(separator + 1U));
                if (key.empty())
                {
                    add_parse_finding(findings, "line " + std::to_string(line_number), "expected key=value");
                }
                else if (contains_key(seen_keys, key))
                {
                    add_parse_finding(findings, std::string{key}, "duplicate configuration key");
                }
                else
                {
                    seen_keys.emplace_back(key);
                    apply_config_value(server, listeners, database, security, key, value, findings);
                }
            }
        }

        if (newline == std::string_view::npos)
        {
            break;
        }
        input = input.substr(newline + 1U);
        ++line_number;
    }

    auto config = Config{server, listeners, database, security};
    auto validation_findings = validate(config);
    findings.insert(findings.end(), validation_findings.begin(), validation_findings.end());

    return {config, findings};
}

} // namespace merovingian::config
