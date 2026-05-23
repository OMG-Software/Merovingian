// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation/runtime_federation.hpp"

#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"

#include <string>
#include <utility>
#include <vector>

namespace merovingian::federation
{
namespace
{

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields) -> void
    {
        LOG_DEBUG(observability::diagnostic_log_summary("federation_policy", event, std::move(fields)));
    }

    [[nodiscard]] auto contains_server(std::vector<std::string> const& servers, std::string_view server_name) noexcept
        -> bool
    {
        for (auto const& server : servers)
        {
            if (server == server_name)
            {
                return true;
            }
        }

        return false;
    }

} // namespace

auto make_runtime_federation_config(config::Config const& config) -> RuntimeFederationConfig
{
    auto const max_transaction_size = config::parse_size_limit(config.security().federation.max_transaction_size);
    auto const remote_timeout = config::parse_duration_seconds(config.security().federation.remote_timeout);

    return {
        config.security().federation.enabled,
        config.security().federation.default_policy,
        config.security().federation.allowed_servers,
        config.security().federation.denied_servers,
        config.security().federation.require_valid_tls,
        config.security().federation.verify_json_signatures,
        config.security().federation.deny_ip_ranges,
        max_transaction_size.valid ? max_transaction_size.bytes : 0U,
        remote_timeout.valid ? remote_timeout.seconds : 0U,
        config.server().server_name,
    };
}

auto federation_summary(RuntimeFederationConfig const& config) -> std::string
{
    return "Federation runtime config: enabled=" + std::string{config.enabled ? "true" : "false"} +
           " default_policy=" + config.default_policy +
           " allowed_servers=" + std::to_string(config.allowed_servers.size()) +
           " denied_servers=" + std::to_string(config.denied_servers.size()) +
           " max_transaction_bytes=" + std::to_string(config.max_transaction_bytes) +
           " remote_timeout_seconds=" + std::to_string(config.remote_timeout_seconds);
}

auto federation_server_policy(RuntimeFederationConfig const& config, std::string_view server_name)
    -> FederationServerPolicyDecision
{
    auto result = [&]() -> FederationServerPolicyDecision {
        if (!config.enabled)
        {
            return {false, "federation disabled"};
        }
        if (server_name.empty())
        {
            return {false, "remote server name is empty"};
        }
        if (contains_server(config.denied_servers, server_name))
        {
            return {false, "remote server is denied"};
        }
        if (config.default_policy == "deny" && !contains_server(config.allowed_servers, server_name))
        {
            return {false, "remote server is not in federation allow list"};
        }
        return {true, {}};
    }();
    log_diagnostic(result.allowed ? "server_policy.allowed" : "server_policy.denied",
                   {{"server_name", std::string{server_name}, false},
                    {"reason",      result.reason,            false}});
    return result;
}

} // namespace merovingian::federation
