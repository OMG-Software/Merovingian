// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/federation/runtime_federation.hpp>

#include <string>
#include <utility>

namespace merovingian::federation
{

auto make_runtime_federation_config(config::Config const& config) -> RuntimeFederationConfig
{
    auto const max_transaction_size = config::parse_size_limit(config.security().federation.max_transaction_size);
    auto const remote_timeout = config::parse_duration_seconds(config.security().federation.remote_timeout);

    return {
        config.security().federation.enabled,
        config.security().federation.default_policy,
        config.security().federation.require_valid_tls,
        config.security().federation.verify_json_signatures,
        config.security().federation.deny_ip_ranges,
        max_transaction_size.valid ? max_transaction_size.bytes : 0U,
        remote_timeout.valid ? remote_timeout.seconds : 0U,
    };
}

auto federation_summary(RuntimeFederationConfig const& config) -> std::string
{
    return "Federation runtime config: enabled=" + std::string{config.enabled ? "true" : "false"}
        + " default_policy=" + config.default_policy
        + " max_transaction_bytes=" + std::to_string(config.max_transaction_bytes)
        + " remote_timeout_seconds=" + std::to_string(config.remote_timeout_seconds);
}

} // namespace merovingian::federation
