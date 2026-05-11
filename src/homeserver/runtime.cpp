// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/homeserver/vertical_slice.hpp>

#include "local_services.hpp"

#include <merovingian/database/schema.hpp>
#include <merovingian/federation/runtime_federation.hpp>
#include <merovingian/platform/hardening_self_check.hpp>

#include <algorithm>
#include <string>
#include <string_view>
#include <utility>

namespace merovingian::homeserver
{

auto bootstrap_local_database(config::Config const& config) -> LocalDatabase
{
    return bootstrap_local_database(config, {});
}

auto bootstrap_local_database(config::Config const&, database::SchemaState existing_state) -> LocalDatabase
{
    auto database = LocalDatabase{};
    auto opened = database::open_persistent_store(std::move(existing_state));
    if (!opened.ok)
    {
        return database;
    }

    database.opened = true;
    database.persistent_store = std::move(opened.store);
    database.schema_validated = database::validate_persistent_store(database.persistent_store).valid;
    database.schema_version = database.persistent_store.schema.version;
    database.tables = database.persistent_store.schema.tables;
    return database;
}

auto database_has_table(LocalDatabase const& database, std::string_view table_name) noexcept -> bool
{
    return std::ranges::any_of(database.tables, [table_name](std::string const& table) { return table == table_name; });
}

auto start_runtime(config::Config const& config) -> RuntimeStartResult
{
    return start_runtime(config, {});
}

auto start_runtime(config::Config const& config, database::SchemaState existing_state) -> RuntimeStartResult
{
    if (!config::is_valid(config))
    {
        return {false, "configuration is invalid", {}};
    }

    auto runtime = HomeserverRuntime{};
    runtime.config = config;
    runtime.listeners = net::make_runtime_listeners(config);
    if (runtime.listeners.empty())
    {
        return {false, "no runtime listeners configured", {}};
    }

    runtime.database = bootstrap_local_database(config, std::move(existing_state));
    if (!runtime.database.opened || !runtime.database.schema_validated || !database_has_table(runtime.database, "users")
        || !database_has_table(runtime.database, "devices") || !database_has_table(runtime.database, "access_tokens")
        || !database_has_table(runtime.database, "rooms") || !database_has_table(runtime.database, "membership")
        || !database_has_table(runtime.database, "events") || !database_has_table(runtime.database, "current_state")
        || !database_has_table(runtime.database, "audit_log") || !database_has_table(runtime.database, "admin_actions"))
    {
        return {false, "database schema validation failed", {}};
    }

    runtime.federation = federation::make_federation_runtime_state(federation::make_runtime_federation_config(config));
    runtime.hardening = platform::run_startup_hardening_self_check();
    append_local_audit(runtime.database, observability::AuditCategory::admin, "runtime.started", "server", "homeserver", "startup");
    runtime.started = true;
    return {true, {}, std::move(runtime)};
}

auto admin_health(HomeserverRuntime const& runtime) -> observability::HealthCheckSnapshot
{
    auto snapshot = observability::HealthCheckSnapshot{};
    snapshot.components = {
        {"runtime", runtime.started ? observability::HealthStatus::ok : observability::HealthStatus::failed, "started"},
        {"listeners", runtime.listeners.empty() ? observability::HealthStatus::failed : observability::HealthStatus::ok, "configured"},
        {"database", runtime.database.schema_validated ? observability::HealthStatus::ok : observability::HealthStatus::failed, "schema_validated"},
        {"federation", runtime.federation.config.enabled ? observability::HealthStatus::ok : observability::HealthStatus::degraded, federation::federation_runtime_summary(runtime.federation)},
        {"hardening", runtime.hardening.count() > 0U ? observability::HealthStatus::ok : observability::HealthStatus::degraded, "self_check"},
    };

    for (auto const& component : snapshot.components)
    {
        if (component.status == observability::HealthStatus::failed)
        {
            snapshot.status = observability::HealthStatus::failed;
            return snapshot;
        }
        if (component.status == observability::HealthStatus::degraded)
        {
            snapshot.status = observability::HealthStatus::degraded;
        }
    }
    return snapshot;
}

auto admin_health_summary(HomeserverRuntime const& runtime) -> std::string
{
    return observability::health_snapshot_summary(admin_health(runtime));
}

} // namespace merovingian::homeserver
