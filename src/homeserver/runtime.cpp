// SPDX-License-Identifier: GPL-3.0-or-later

#include "local_services.hpp"
#include "merovingian/database/postgresql_store.hpp"
#include "merovingian/database/schema.hpp"
#include "merovingian/federation/runtime_federation.hpp"
#include "merovingian/homeserver/vertical_slice.hpp"
#include "merovingian/media/runtime_media.hpp"
#include "merovingian/platform/hardening_self_check.hpp"

#include <algorithm>
#include <cstddef>
#include <fstream>
#include <string>
#include <string_view>
#include <utility>

namespace merovingian::homeserver
{
namespace
{

    [[nodiscard]] auto read_database_uri_file(std::string const& path) -> std::string
    {
        auto input = std::ifstream{path};
        if (!input.is_open())
        {
            return {};
        }
        auto value = std::string{};
        std::getline(input, value);
        return value;
    }

} // namespace

auto bootstrap_local_database(config::Config const& config) -> LocalDatabase
{
    return bootstrap_local_database(config, {});
}

auto hydrate_local_database(LocalDatabase& database) -> void
{
    database.users.reserve(database.persistent_store.users.size());
    for (auto const& user : database.persistent_store.users)
    {
        database.users.push_back({user.user_id, user.password_hash, user.locked, user.suspended, user.admin});
    }

    database.sessions.reserve(database.persistent_store.access_tokens.size());
    for (auto const& token : database.persistent_store.access_tokens)
    {
        database.sessions.push_back({token.user_id, token.device_id, token.token_hash, token.revoked});
    }

    database.rooms.reserve(database.persistent_store.rooms.size());
    for (auto const& room : database.persistent_store.rooms)
    {
        database.rooms.push_back({room.room_id, room.creator_user_id, {}, {}});
    }

    for (auto const& membership : database.persistent_store.memberships)
    {
        auto room = std::ranges::find_if(database.rooms, [&membership](LocalRoom const& candidate) {
            return candidate.room_id == membership.room_id;
        });
        if (room != database.rooms.end() &&
            !std::ranges::any_of(room->members, [&membership](std::string const& user_id) {
                return user_id == membership.user_id;
            }))
        {
            room->members.push_back(membership.user_id);
        }
    }

    for (auto const& event : database.persistent_store.events)
    {
        auto room = std::ranges::find_if(database.rooms, [&event](LocalRoom const& candidate) {
            return candidate.room_id == event.room_id;
        });
        if (room != database.rooms.end())
        {
            room->events.push_back(event.json);
        }
    }

    database.next_session_id = static_cast<std::uint64_t>(database.sessions.size()) + 1U;
    database.next_event_id = static_cast<std::uint64_t>(database.persistent_store.events.size()) + 1U;
    for (auto const& event : database.persistent_store.events)
    {
        if (event.stream_ordering >= database.next_stream_ordering)
        {
            database.next_stream_ordering = event.stream_ordering + 1U;
        }
    }
}

auto bootstrap_local_database(config::Config const& config, database::SchemaState existing_state) -> LocalDatabase
{
    auto database = LocalDatabase{};
    auto opened = database::PersistentStoreOpenResult{};
    if (config.database().backend == config::DatabaseBackend::sqlite)
    {
        opened = database::open_sqlite_persistent_store(config.database().sqlite_path);
    }
    else
    {
        auto const conninfo = read_database_uri_file(config.database().uri_file);
        opened = conninfo.empty() ? database::open_persistent_store(std::move(existing_state))
                                  : database::open_postgresql_persistent_store(conninfo);
    }
    if (!opened.ok)
    {
        return database;
    }

    database.opened = true;
    database.persistent_store = std::move(opened.store);
    database.schema_validated = database::validate_persistent_store(database.persistent_store).valid;
    database.schema_version = database.persistent_store.schema.version;
    database.tables = database.persistent_store.schema.tables;
    hydrate_local_database(database);
    return database;
}

auto database_has_table(LocalDatabase const& database, std::string_view table_name) noexcept -> bool
{
    return std::ranges::any_of(database.tables, [table_name](std::string const& table) {
        return table == table_name;
    });
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
    if (config.database().role != config::DatabaseRole::runtime)
    {
        return {false, "runtime requires database.role=runtime", {}};
    }

    auto runtime = HomeserverRuntime{};
    runtime.config = config;
    runtime.listeners = net::make_runtime_listeners(config);
    if (runtime.listeners.empty())
    {
        return {false, "no runtime listeners configured", {}};
    }

    runtime.database = bootstrap_local_database(config, std::move(existing_state));
    if (!runtime.database.opened || !runtime.database.schema_validated ||
        !database_has_table(runtime.database, "users") || !database_has_table(runtime.database, "devices") ||
        !database_has_table(runtime.database, "access_tokens") || !database_has_table(runtime.database, "rooms") ||
        !database_has_table(runtime.database, "membership") || !database_has_table(runtime.database, "events") ||
        !database_has_table(runtime.database, "current_state") || !database_has_table(runtime.database, "media") ||
        !database_has_table(runtime.database, "device_keys") ||
        !database_has_table(runtime.database, "one_time_keys") ||
        !database_has_table(runtime.database, "fallback_keys") ||
        !database_has_table(runtime.database, "cross_signing_keys") ||
        !database_has_table(runtime.database, "key_signatures") ||
        !database_has_table(runtime.database, "key_backup_versions") ||
        !database_has_table(runtime.database, "key_backup_sessions") ||
        !database_has_table(runtime.database, "remote_media") || !database_has_table(runtime.database, "audit_log") ||
        !database_has_table(runtime.database, "admin_actions"))
    {
        return {false, "database schema validation failed", {}};
    }

    runtime.federation = federation::make_federation_runtime_state(federation::make_runtime_federation_config(config));
    runtime.media_repository = media::make_local_media_repository(media::make_runtime_media_config(config));
    runtime.hardening = platform::run_startup_hardening_self_check();
    append_local_audit(runtime.database, observability::AuditCategory::admin, "runtime.started", "server", "homeserver",
                       "startup");
    runtime.started = true;
    return {true, {}, std::move(runtime)};
}

auto admin_health(HomeserverRuntime const& runtime) -> observability::HealthCheckSnapshot
{
    auto snapshot = observability::HealthCheckSnapshot{};
    auto const federation_detail = runtime.federation.config.enabled
                                       ? federation::federation_runtime_summary(runtime.federation)
                                       : std::string{"federation disabled by configuration"};
    auto const media_detail = media::media_repository_summary(runtime.media_repository);
    snapshot.components = {
        {"runtime",    runtime.started ? observability::HealthStatus::ok : observability::HealthStatus::failed,           "started"        },
        {"listeners",  runtime.listeners.empty() ? observability::HealthStatus::failed : observability::HealthStatus::ok,
         "configured"                                                                                                                      },
        {"database",
         runtime.database.schema_validated ? observability::HealthStatus::ok : observability::HealthStatus::failed,
         "schema_validated"                                                                                                                },
        {"federation", observability::HealthStatus::ok,                                                                   federation_detail},
        {"media",
         runtime.media_repository.config.max_upload_bytes > 0U ? observability::HealthStatus::ok
                                                               : observability::HealthStatus::failed,
         media_detail                                                                                                                      },
        {"hardening",
         runtime.hardening.count() > 0U ? observability::HealthStatus::ok : observability::HealthStatus::degraded,
         "self_check"                                                                                                                      },
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

auto admin_metrics_summary(HomeserverRuntime const& runtime) -> std::string
{
    auto const& store = runtime.database.persistent_store;
    return "metrics users_total=" + std::to_string(store.users.size()) +
           " sessions_total=" + std::to_string(store.access_tokens.size()) +
           " rooms_total=" + std::to_string(store.rooms.size()) +
           " events_total=" + std::to_string(store.events.size()) +
           " audit_events_appended_total=" + std::to_string(store.audit_log.size()) +
           " admin_actions_total=" + std::to_string(store.admin_actions.size());
}

auto admin_audit_summary(HomeserverRuntime const& runtime) -> std::string
{
    auto summary = std::string{"audit events="} + std::to_string(runtime.database.persistent_store.audit_log.size());
    for (auto const& event : runtime.database.persistent_store.audit_log)
    {
        summary += " entry=" + event.category + ':' + event.event_type + ':' + event.actor + ':' + event.target + ':' +
                   event.reason;
    }
    return summary;
}

} // namespace merovingian::homeserver
