// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/config/config_parser.hpp"

#include "merovingian/http/rate_limit.hpp"
#include "merovingian/observability/logger.hpp"

#include <algorithm>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
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
                                   SecurityConfig& security, ClientRateLimitsConfig& client_rate_limits,
                                   LogModulesConfig& log_modules, FederationWorkerConfig& federation_worker,
                                   std::string_view key, std::string_view value,
                                   std::vector<ConfigValidationFinding>& findings) -> void
    {
        // The client_rate_limits.per_ip, .per_user and .tier maps are keyed
        // by request target prefix (e.g. "/_matrix/client/v3/login") or tier
        // name, both of which contain '/' or '_' characters. We handle them
        // with prefix-matching before the literal-key branches so the rest
        // of the parser remains a clean if/else chain.
        if (starts_with(key, "client_rate_limits.per_ip."))
        {
            auto const target = std::string{key.substr(std::string_view{"client_rate_limits.per_ip."}.size())};
            auto const policy = parse_rate_limit_policy(value);
            if (!policy.has_value())
            {
                add_parse_finding(findings, std::string{key},
                                  "expected rate-limit policy of the form N/Ns (e.g. 20/60s)");
            }
            else
            {
                client_rate_limits.per_ip[target] = *policy;
            }
            return;
        }
        if (starts_with(key, "client_rate_limits.per_user."))
        {
            auto const target = std::string{key.substr(std::string_view{"client_rate_limits.per_user."}.size())};
            auto const policy = parse_rate_limit_policy(value);
            if (!policy.has_value())
            {
                add_parse_finding(findings, std::string{key},
                                  "expected rate-limit policy of the form N/Ns (e.g. 5/60s)");
            }
            else
            {
                client_rate_limits.per_user[target] = *policy;
            }
            return;
        }
        if (starts_with(key, "client_rate_limits.tier."))
        {
            // Tier names are validated against the engine's tier table so a
            // typo (e.g. client_rate_limits.tier.login) becomes a parse
            // finding instead of a silently ignored key.
            auto const name = key.substr(std::string_view{"client_rate_limits.tier."}.size());
            auto const policy = parse_rate_limit_policy(value);
            if (!http::rate_limit_tier_from_name(name).has_value())
            {
                add_parse_finding(findings, std::string{key},
                                  "unknown rate-limit tier; expected one of auth_sensitive, media, sync, federation, "
                                  "admin, generic");
            }
            else if (!policy.has_value())
            {
                add_parse_finding(findings, std::string{key},
                                  "expected rate-limit policy of the form N/Ns (e.g. 20/60s)");
            }
            else
            {
                client_rate_limits.tier[std::string{name}] = *policy;
            }
            return;
        }
        if (key == "client_rate_limits.default_per_ip")
        {
            auto const policy = parse_rate_limit_policy(value);
            if (!policy.has_value())
            {
                add_parse_finding(findings, std::string{key},
                                  "expected rate-limit policy of the form N/Ns (e.g. 60/60s)");
            }
            else
            {
                client_rate_limits.default_per_ip = *policy;
            }
            return;
        }
        if (starts_with(key, "log_modules."))
        {
            auto const name = std::string{key.substr(std::string_view{"log_modules."}.size())};
            auto const level = parse_log_level(value);
            if (!level.has_value())
            {
                add_parse_finding(findings, std::string{key},
                                  "expected log level trace|debug|info|notice|warning|error|critical|off");
            }
            else
            {
                log_modules.levels[name] = *level;
            }
            return;
        }

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
        else if (key == "server.cors.allowed_origins")
        {
            server.cors.allowed_origins = parse_string_list(value);
        }
        else if (key == "server.cors.allow_methods")
        {
            server.cors.allow_methods = std::string{value};
        }
        else if (key == "server.cors.allow_headers")
        {
            server.cors.allow_headers = std::string{value};
        }
        else if (key == "server.cors.allow_credentials")
        {
            if (!parse_bool_value(value, server.cors.allow_credentials))
            {
                add_parse_finding(findings, std::string{key}, "expected boolean value");
            }
        }
        else if (key == "server.cors.max_age")
        {
            try
            {
                auto const parsed = std::stoul(std::string{value});
                if (parsed > std::numeric_limits<std::uint32_t>::max())
                {
                    add_parse_finding(findings, std::string{key}, "value too large for uint32");
                }
                else
                {
                    server.cors.max_age = static_cast<std::uint32_t>(parsed);
                }
            }
            catch (...)
            {
                add_parse_finding(findings, std::string{key}, "expected non-negative integer");
            }
        }
        else if (key == "server.http.keep_alive")
        {
            if (!parse_bool_value(value, server.http.keep_alive))
            {
                add_parse_finding(findings, std::string{key}, "expected boolean value");
            }
        }
        else if (key == "server.http.keep_alive_idle_seconds")
        {
            try
            {
                auto const parsed = std::stoul(std::string{value});
                if (parsed == 0U || parsed > std::numeric_limits<std::uint32_t>::max())
                {
                    add_parse_finding(findings, std::string{key}, "expected positive integer");
                }
                else
                {
                    server.http.keep_alive_idle_seconds = static_cast<std::uint32_t>(parsed);
                }
            }
            catch (...)
            {
                add_parse_finding(findings, std::string{key}, "expected positive integer");
            }
        }
        else if (key == "server.http.keep_alive_max_connections")
        {
            try
            {
                auto const parsed = std::stoul(std::string{value});
                if (parsed == 0U || parsed > std::numeric_limits<std::uint32_t>::max())
                {
                    add_parse_finding(findings, std::string{key}, "expected positive integer");
                }
                else
                {
                    server.http.keep_alive_max_connections = static_cast<std::uint32_t>(parsed);
                }
            }
            catch (...)
            {
                add_parse_finding(findings, std::string{key}, "expected positive integer");
            }
        }
        else if (key == "server.turn.server")
        {
            server.turn.server = std::string{value};
        }
        else if (key == "server.turn.username")
        {
            server.turn.username = std::string{value};
        }
        else if (key == "server.turn.password")
        {
            server.turn.password = std::string{value};
        }
        else if (key == "server.turn.ttl_seconds")
        {
            try
            {
                auto const parsed = std::stoul(std::string{value});
                if (parsed == 0U || parsed > std::numeric_limits<std::uint32_t>::max())
                {
                    add_parse_finding(findings, std::string{key}, "expected positive integer");
                }
                else
                {
                    server.turn.ttl_seconds = static_cast<std::uint32_t>(parsed);
                }
            }
            catch (...)
            {
                add_parse_finding(findings, std::string{key}, "expected positive integer");
            }
        }
        else if (key == "server.oidc.enabled")
        {
            if (!parse_bool_value(value, server.oidc.enabled))
            {
                add_parse_finding(findings, std::string{key}, "expected boolean value");
            }
        }
        else if (key == "server.oidc.issuer")
        {
            server.oidc.issuer = std::string{value};
        }
        else if (key == "server.oidc.authorization_endpoint")
        {
            server.oidc.authorization_endpoint = std::string{value};
        }
        else if (key == "server.oidc.token_endpoint")
        {
            server.oidc.token_endpoint = std::string{value};
        }
        else if (key == "server.oidc.registration_endpoint")
        {
            server.oidc.registration_endpoint = std::string{value};
        }
        else if (key == "server.oidc.revocation_endpoint")
        {
            server.oidc.revocation_endpoint = std::string{value};
        }
        else if (key == "server.oidc.device_authorization_endpoint")
        {
            server.oidc.device_authorization_endpoint = std::string{value};
        }
        else if (key == "server.oidc.account_management_uri")
        {
            server.oidc.account_management_uri = std::string{value};
        }
        else if (key == "server.oidc.account_management_actions_supported")
        {
            server.oidc.account_management_actions_supported = parse_string_list(value);
        }
        else if (key == "server.identity_server.trusted_servers")
        {
            server.identity_server.trusted_servers = parse_string_list(value);
        }
        else if (key == "server.identity_server.default_server")
        {
            server.identity_server.default_server = std::string{value};
        }
        else if (key == "server.identity_server.allowed_bind_domains")
        {
            server.identity_server.allowed_bind_domains = parse_string_list(value);
        }
        else if (key == "server.identity_server.connect_timeout_seconds")
        {
            try
            {
                auto const parsed = std::stoul(std::string{value});
                if (parsed == 0U || parsed > std::numeric_limits<std::uint32_t>::max())
                {
                    add_parse_finding(findings, std::string{key}, "expected positive integer");
                }
                else
                {
                    server.identity_server.connect_timeout_seconds = static_cast<std::uint32_t>(parsed);
                }
            }
            catch (...)
            {
                add_parse_finding(findings, std::string{key}, "expected positive integer");
            }
        }
        else if (key == "server.identity_server.total_timeout_seconds")
        {
            try
            {
                auto const parsed = std::stoul(std::string{value});
                if (parsed == 0U || parsed > std::numeric_limits<std::uint32_t>::max())
                {
                    add_parse_finding(findings, std::string{key}, "expected positive integer");
                }
                else
                {
                    server.identity_server.total_timeout_seconds = static_cast<std::uint32_t>(parsed);
                }
            }
            catch (...)
            {
                add_parse_finding(findings, std::string{key}, "expected positive integer");
            }
        }
        else if (key == "server.push.enabled")
        {
            if (!parse_bool_value(value, server.push.enabled))
            {
                add_parse_finding(findings, std::string{key}, "expected boolean value");
            }
        }
        else if (key == "server.push.connect_timeout_seconds")
        {
            try
            {
                auto const parsed = std::stoul(std::string{value});
                if (parsed == 0U || parsed > std::numeric_limits<std::uint32_t>::max())
                {
                    add_parse_finding(findings, std::string{key}, "expected positive integer");
                }
                else
                {
                    server.push.connect_timeout_seconds = static_cast<std::uint32_t>(parsed);
                }
            }
            catch (...)
            {
                add_parse_finding(findings, std::string{key}, "expected positive integer");
            }
        }
        else if (key == "server.push.total_timeout_seconds")
        {
            try
            {
                auto const parsed = std::stoul(std::string{value});
                if (parsed == 0U || parsed > std::numeric_limits<std::uint32_t>::max())
                {
                    add_parse_finding(findings, std::string{key}, "expected positive integer");
                }
                else
                {
                    server.push.total_timeout_seconds = static_cast<std::uint32_t>(parsed);
                }
            }
            catch (...)
            {
                add_parse_finding(findings, std::string{key}, "expected positive integer");
            }
        }
        else if (key == "server.sso.enabled")
        {
            if (!parse_bool_value(value, server.sso.enabled))
            {
                add_parse_finding(findings, std::string{key}, "expected boolean value");
            }
        }
        else if (key == "server.sso.authorization_url")
        {
            server.sso.authorization_url = std::string{value};
        }
        else if (key == "server.sso.redirect_url_allowlist")
        {
            server.sso.redirect_url_allowlist = parse_string_list(value);
        }
        else if (starts_with(key, "server.sso.identity_providers."))
        {
            // Keyed as server.sso.identity_providers.<idpId>.<field>. idpId
            // is an opaque identifier (spec: Opaque identifier Grammar) that
            // may itself contain dots (reverse-DNS-style, e.g.
            // "com.example.idp.github"), so the *last* dot-delimited segment
            // is always the field name and everything before it is the id.
            auto const rest = key.substr(std::string_view{"server.sso.identity_providers."}.size());
            auto const last_dot = rest.rfind('.');
            if (last_dot == std::string_view::npos || last_dot == 0U || last_dot + 1U >= rest.size())
            {
                add_parse_finding(findings, std::string{key},
                                  "expected server.sso.identity_providers.<idpId>.<name|icon|brand>");
                return;
            }
            auto const idp_id = std::string{rest.substr(0U, last_dot)};
            auto const field = rest.substr(last_dot + 1U);
            auto existing =
                std::ranges::find_if(server.sso.identity_providers, [&idp_id](SsoIdentityProvider const& idp) {
                    return idp.id == idp_id;
                });
            if (existing == server.sso.identity_providers.end())
            {
                server.sso.identity_providers.push_back(SsoIdentityProvider{idp_id, {}, {}, {}});
                existing = std::prev(server.sso.identity_providers.end());
            }
            if (field == "name")
            {
                existing->name = std::string{value};
            }
            else if (field == "icon")
            {
                existing->icon = std::string{value};
            }
            else if (field == "brand")
            {
                existing->brand = std::string{value};
            }
            else
            {
                add_parse_finding(findings, std::string{key}, "expected field name|icon|brand");
            }
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
        else if (key == "listeners.client.reverse_proxy")
        {
            if (!parse_bool_value(value, listeners.client.reverse_proxy))
            {
                add_parse_finding(findings, std::string{key}, "expected boolean value");
            }
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
        else if (key == "listeners.federation.reverse_proxy")
        {
            if (!parse_bool_value(value, listeners.federation.reverse_proxy))
            {
                add_parse_finding(findings, std::string{key}, "expected boolean value");
            }
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
        else if (key == "database.role")
        {
            auto const role = parse_database_role(value);
            if (role.has_value())
            {
                database.role = *role;
            }
            else
            {
                add_parse_finding(findings, std::string{key}, "expected database role runtime or migration");
            }
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
        else if (key == "security.registration.token_file")
        {
            security.registration.token_file = std::string{value};
        }
        else if (key == "security.access_token_lifetime_ms")
        {
            if (!parse_i64_value(value, security.access_token_lifetime_ms))
            {
                add_parse_finding(findings, std::string{key}, "expected integer millisecond value");
            }
        }
        else if (key == "security.refresh_token_lifetime_ms")
        {
            if (!parse_i64_value(value, security.refresh_token_lifetime_ms))
            {
                add_parse_finding(findings, std::string{key}, "expected integer millisecond value");
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
        else if (key == "security.federation.max_transaction_pdus")
        {
            if (!parse_u32_value(value, security.federation.max_transaction_pdus))
            {
                add_parse_finding(findings, std::string{key}, "expected unsigned integer value");
            }
        }
        else if (key == "security.federation.max_transaction_edus")
        {
            if (!parse_u32_value(value, security.federation.max_transaction_edus))
            {
                add_parse_finding(findings, std::string{key}, "expected unsigned integer value");
            }
        }
        else if (key == "security.federation.per_origin_transaction_rate")
        {
            auto const policy = parse_rate_limit_policy(value);
            if (!policy.has_value())
            {
                add_parse_finding(findings, std::string{key},
                                  "expected rate-limit policy of the form N/Ns (e.g. 120/60s)");
            }
            else
            {
                security.federation.per_origin_transaction_rate = *policy;
            }
        }
        else if (key == "security.federation.per_origin_pdu_rate")
        {
            auto const policy = parse_rate_limit_policy(value);
            if (!policy.has_value())
            {
                add_parse_finding(findings, std::string{key},
                                  "expected rate-limit policy of the form N/Ns (e.g. 600/60s)");
            }
            else
            {
                security.federation.per_origin_pdu_rate = *policy;
            }
        }
        else if (key == "security.federation.per_origin_edu_rate")
        {
            auto const policy = parse_rate_limit_policy(value);
            if (!policy.has_value())
            {
                add_parse_finding(findings, std::string{key},
                                  "expected rate-limit policy of the form N/Ns (e.g. 1200/60s)");
            }
            else
            {
                security.federation.per_origin_edu_rate = *policy;
            }
        }
        else if (key == "security.federation.per_origin_request_rate")
        {
            auto const policy = parse_rate_limit_policy(value);
            if (!policy.has_value())
            {
                add_parse_finding(findings, std::string{key},
                                  "expected rate-limit policy of the form N/Ns (e.g. 600/60s)");
            }
            else
            {
                security.federation.per_origin_request_rate = *policy;
            }
        }
        else if (key == "security.federation.remote_timeout")
        {
            security.federation.remote_timeout = std::string{value};
        }
        else if (key == "security.federation.join_timeout")
        {
            security.federation.join_timeout = std::string{value};
        }
        else if (key == "security.federation.join_parallelism")
        {
            if (!parse_u32_value(value, security.federation.join_parallelism))
            {
                add_parse_finding(findings, std::string{key}, "expected unsigned integer");
            }
        }
        else if (key == "security.federation.join_race_deadline")
        {
            security.federation.join_race_deadline = std::string{value};
        }
        else if (key == "security.federation.join_max_candidates")
        {
            if (!parse_u32_value(value, security.federation.join_max_candidates))
            {
                add_parse_finding(findings, std::string{key}, "expected unsigned integer");
            }
        }
        else if (key == "security.federation.join_state_key_parallelism")
        {
            if (!parse_u32_value(value, security.federation.join_state_key_parallelism))
            {
                add_parse_finding(findings, std::string{key}, "expected unsigned integer");
            }
        }
        else if (key == "security.federation.join_response_max_size")
        {
            security.federation.join_response_max_size = std::string{value};
        }
        else if (key == "security.media.max_upload_size")
        {
            security.media.max_upload_size = std::string{value};
        }
        else if (key == "security.media.allowed_mime_types")
        {
            security.media.allowed_mime_types = parse_string_list(value);
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
        else if (key == "security.media.local_upload_policy")
        {
            security.media.local_upload_policy = std::string{value};
        }
        else if (key == "security.media.remote_fetch_media_policy")
        {
            security.media.remote_fetch_media_policy = std::string{value};
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
        else if (key == "security.media.remote_fetch_enabled")
        {
            if (!parse_bool_value(value, security.media.remote_fetch_enabled))
            {
                add_parse_finding(findings, std::string{key}, "expected boolean value");
            }
        }
        else if (key == "security.media.decode_in_sandbox")
        {
            if (!parse_bool_value(value, security.media.decode_in_sandbox))
            {
                add_parse_finding(findings, std::string{key}, "expected boolean value");
            }
        }
        else if (key == "security.trust_safety.enabled")
        {
            if (!parse_bool_value(value, security.trust_safety.enabled))
            {
                add_parse_finding(findings, std::string{key}, "expected boolean value");
            }
        }
        else if (key == "security.trust_safety.policy_server_url")
        {
            security.trust_safety.policy_server_url = std::string{value};
        }
        else if (key == "security.trust_safety.policy_server_timeout")
        {
            security.trust_safety.policy_server_timeout = std::string{value};
        }
        else if (key == "security.trust_safety.policy_server_allow_without_result")
        {
            if (!parse_bool_value(value, security.trust_safety.policy_server_allow_without_result))
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
        else if (key == "security.secrets.master_key_file")
        {
            security.secrets.master_key_file = std::string{value};
        }
        else if (key == "federation.worker.request_timeout_seconds")
        {
            if (!parse_u32_value(value, federation_worker.request_timeout_seconds))
            {
                add_parse_finding(findings, std::string{key}, "expected unsigned integer");
            }
        }
        else if (key == "federation.worker.threads")
        {
            if (!parse_u32_value(value, federation_worker.threads))
            {
                add_parse_finding(findings, std::string{key}, "expected unsigned integer");
            }
        }
        else if (key == "federation.worker.relay_threads")
        {
            if (!parse_u32_value(value, federation_worker.relay_threads))
            {
                add_parse_finding(findings, std::string{key}, "expected unsigned integer");
            }
        }
        else if (key == "federation.worker.shards")
        {
            if (!parse_u32_value(value, federation_worker.shards))
            {
                add_parse_finding(findings, std::string{key}, "expected unsigned integer");
            }
        }
        else if (key == "federation.worker.binary")
        {
            federation_worker.worker_binary = std::string{value};
        }
        else if (key == "federation.worker.apply_hardening")
        {
            if (!parse_bool_value(value, federation_worker.apply_hardening))
            {
                add_parse_finding(findings, std::string{key}, "expected boolean (true/false)");
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

auto parse_i64_value(std::string_view value, std::int64_t& output) noexcept -> bool
{
    if (value.empty())
    {
        return false;
    }
    auto index = std::size_t{0U};
    auto negative = false;
    if (value.front() == '+' || value.front() == '-')
    {
        negative = (value.front() == '-');
        index = 1U;
        if (value.size() == 1U)
        {
            return false;
        }
    }
    // Accumulate the magnitude unsigned: INT64_MIN's magnitude (2^63) is one
    // more than INT64_MAX, so a signed accumulator cannot represent it (#455).
    auto const limit = negative ? static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()) + 1ULL
                                : static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
    auto parsed = std::uint64_t{0U};
    for (; index < value.size(); ++index)
    {
        auto const character = value[index];
        if (!is_ascii_digit(character))
        {
            return false;
        }
        auto const digit = static_cast<std::uint64_t>(character - '0');
        if (parsed > (limit - digit) / 10ULL)
        {
            return false;
        }
        parsed = (parsed * 10ULL) + digit;
    }
    // Two's complement: negating in unsigned space then casting yields
    // INT64_MIN for magnitude 2^63 without signed overflow.
    output = negative ? static_cast<std::int64_t>(0ULL - parsed) : static_cast<std::int64_t>(parsed);
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
    auto client_rate_limits = ClientRateLimitsConfig{};
    auto log_modules = LogModulesConfig{};
    auto federation_worker = FederationWorkerConfig{};
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
                    apply_config_value(server, listeners, database, security, client_rate_limits, log_modules,
                                       federation_worker, key, value, findings);
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

    auto config = Config{server, listeners, database, security, client_rate_limits, log_modules, federation_worker};
    auto validation_findings = validate(config);
    findings.insert(findings.end(), validation_findings.begin(), validation_findings.end());

    return {config, findings};
}

} // namespace merovingian::config
