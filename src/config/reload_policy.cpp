// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/config/reload_policy.hpp"

#include "merovingian/config/config.hpp"

#include <string_view>

namespace merovingian::config
{

auto reload_policy_for_key(std::string_view key) noexcept -> ReloadPolicy
{
    if (key == "server.name" || key == "database.uri_file" || key == "database.role" ||
        key == "listeners.client.tls_certificate_file" || key == "listeners.client.tls_private_key_file" ||
        key == "listeners.federation.tls_certificate_file" || key == "listeners.federation.tls_private_key_file" ||
        key == "security.registration.token_file")
    {
        return ReloadPolicy::restart_required;
    }

    // Per-endpoint rate-limit policies and per-module log level overrides
    // are read once at `start_client_server()` time when the rate-limit
    // engine and the logger module map are constructed. SIGHUP does not
    // rebuild them; the operator must restart. Marking them restart_required
    // here keeps the reload-plan summary honest (an operator running
    // `merovingian-server --plan-config-reload a.conf b.conf` will see the
    // `restart_required` flag for any change to these blocks).
    if (key == "client_rate_limits.default_per_ip" || starts_with(key, "client_rate_limits.per_ip.") ||
        starts_with(key, "client_rate_limits.per_user.") || starts_with(key, "log_modules."))
    {
        return ReloadPolicy::restart_required;
    }

    return ReloadPolicy::reloadable;
}

auto reload_policy_name(ReloadPolicy policy) noexcept -> char const*
{
    switch (policy)
    {
    case ReloadPolicy::reloadable:
        return "reloadable";
    case ReloadPolicy::restart_required:
        return "restart_required";
    }

    return "restart_required";
}

} // namespace merovingian::config
