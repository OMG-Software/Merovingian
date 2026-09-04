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
        key == "database.migration_role" || key == "database.runtime_role" ||
        key == "listeners.client.tls_certificate_file" || key == "listeners.client.tls_private_key_file" ||
        key == "listeners.client.reverse_proxy" || key == "listeners.federation.tls_certificate_file" ||
        key == "listeners.federation.tls_private_key_file" || key == "listeners.federation.reverse_proxy" ||
        key == "security.registration.token_file")
    {
        return ReloadPolicy::restart_required;
    }

    // join_response_max_size also sizes the federation-worker IPC channel's
    // max_frame_bytes (see WorkerPool::WorkerPool), which is fixed for the
    // lifetime of the worker process spawned at startup. Raising the byte cap
    // via SIGHUP would change the per-request OutboundRequest cap immediately
    // but leave the already-running worker's undersized frame budget in
    // place, silently dropping any response that grew into the gap.
    // The key-resolution budgets live in RuntimeFederationConfig, which
    // make_runtime_federation_config builds once at startup and SIGHUP does not
    // rebuild. Reporting these as reloadable would tell an operator a tightened
    // budget had taken effect while the old one stayed live.
    if (starts_with(key, "security.federation.key_resolution_"))
    {
        return ReloadPolicy::restart_required;
    }

    if (key == "security.federation.join_response_max_size")
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
        starts_with(key, "client_rate_limits.per_user.") || starts_with(key, "client_rate_limits.tier.") ||
        starts_with(key, "log_modules."))
    {
        return ReloadPolicy::restart_required;
    }

    // The master key is loaded and zeroised at startup, the federation
    // worker processes are spawned (with their thread pools, shard count and
    // hardening) at startup, and CORS headers and the keep-alive connection
    // policy are wired when the listeners start — SIGHUP cannot re-apply any
    // of these (#421, and the docs/user-manual.md Reloadability policy).
    if (key == "security.secrets.master_key_file" || starts_with(key, "federation.worker.") ||
        starts_with(key, "server.cors.") || starts_with(key, "server.http."))
    {
        return ReloadPolicy::restart_required;
    }

    // Identity Service API: the outbound IS client and the cached SSRF-safe
    // resolver are constructed at startup from the trusted-server allowlist and
    // timeouts. SIGHUP does not rebuild them, so any identity_server change
    // requires a restart (consistent with client_rate_limits and server.cors).
    if (starts_with(key, "server.identity_server."))
    {
        return ReloadPolicy::restart_required;
    }

    // Push Gateway API: the outbound push client and its SSRF-safe resolver
    // are constructed at startup from this block, the same lifecycle as the
    // identity-server client above. SIGHUP does not rebuild them.
    if (starts_with(key, "server.push."))
    {
        return ReloadPolicy::restart_required;
    }

    // Application Service API: the AppserviceRegistry is parsed from the
    // configured registration files once at start_runtime() time and handed
    // out as an immutable, read-only snapshot to every request. SIGHUP does
    // not re-parse or rebuild it, so a registration-file-path change (add,
    // remove, or edit the list) requires a restart, the same lifecycle as
    // federation.worker.* above.
    if (starts_with(key, "appservice."))
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
