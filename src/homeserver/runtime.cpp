// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/runtime.hpp"

#include "merovingian/database/postgresql_store.hpp"
#include "merovingian/database/schema.hpp"
#include "merovingian/federation/runtime_federation.hpp"
#include "merovingian/homeserver/local_services.hpp"
#include "merovingian/homeserver/room_service.hpp"
#include "merovingian/media/repository.hpp"
#include "merovingian/media/runtime_media.hpp"
#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"
#include "merovingian/platform/hardening_self_check.hpp"

#include <algorithm>
#include <cstddef>
#include <fstream>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace merovingian::homeserver
{
namespace
{

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields) -> void
    {
        LOG_DEBUG(observability::diagnostic_log_summary("runtime", event, std::move(fields)));
    }

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

    auto hydrate_media_repository(media::LocalMediaRepository& repository,
                                  database::PersistentStore const& persistent_store) -> void
    {
        auto records = std::vector<media::LocalMediaRecord>{};
        records.reserve(persistent_store.local_media.size());
        for (auto const& media_row : persistent_store.local_media)
        {
            auto record = media::LocalMediaRecord{};
            record.media_id = media_row.media_id;
            record.owner_user_id = media_row.owner_user_id;
            record.content_type = media_row.content_type;
            record.size_bytes = media_row.size_bytes;
            record.hash_algorithm = media_row.hash_algorithm;
            record.digest = media_row.digest;
            record.storage_id = media::make_local_media_storage_id(media_row.digest, media_row.size_bytes);
            record.state = media_row.removed ? media::LocalMediaState::removed
                                             : (media_row.quarantined ? media::LocalMediaState::quarantined
                                                                      : media::LocalMediaState::available);
            record.quarantine_reason = media_row.quarantined ? "persisted quarantine" : std::string{};
            records.push_back(std::move(record));
        }

        auto blobs = std::vector<media::LocalMediaBlob>{};
        blobs.reserve(persistent_store.media_blobs.size());
        for (auto const& blob_row : persistent_store.media_blobs)
        {
            blobs.push_back({blob_row.storage_id, blob_row.hash_algorithm, blob_row.digest, blob_row.size_bytes,
                             blob_row.bytes, blob_row.ref_count});
        }
        media::restore_local_media_repository(repository, std::move(records), std::move(blobs));
    }

} // namespace

HomeserverRuntime::HomeserverRuntime()
    : audit_sink_scope{std::make_unique<LocalDatabaseScope>(database)}
{
}

HomeserverRuntime::~HomeserverRuntime() = default;

HomeserverRuntime::HomeserverRuntime(HomeserverRuntime&& other) noexcept
    : config(std::move(other.config))
    , listeners(std::move(other.listeners))
    , database(std::move(other.database))
    // The source's `audit_sink_scope` is left as-is (still pointing
    // at the source's `database` address). When the source runtime
    // is destroyed, its scope's dtor will see the thread_local now
    // points at the new `database` (this runtime's), and the
    // `current != m_installed` check makes the clear a no-op.
    // Re-install a fresh scope against the new `database` so the
    // thread_local tracks the moved-into runtime, not the source.
    , audit_sink_scope{std::make_unique<LocalDatabaseScope>(database)}
    , federation(std::move(other.federation))
    , media_repository(std::move(other.media_repository))
    , hardening(std::move(other.hardening))
    , started(other.started)
    , outbound_client(std::move(other.outbound_client))
    , discovery_network(std::move(other.discovery_network))
    , dispatch_worker(std::move(other.dispatch_worker))
    , sync_notifier(std::exchange(other.sync_notifier, nullptr))
    , typing_users(std::move(other.typing_users))
    , receipts(std::move(other.receipts))
{
}

auto HomeserverRuntime::operator=(HomeserverRuntime&& other) noexcept -> HomeserverRuntime&
{
    if (this == &other)
    {
        return *this;
    }

    config = std::move(other.config);
    listeners = std::move(other.listeners);
    database = std::move(other.database);
    // `database` is now the new storage; re-seat the audit-sink
    // install on it. The old scope (which pointed at the previous
    // `database` address) is destroyed by `reset()` first; its dtor
    // clears the thread_local only if the install is still ours, so
    // it is always safe to call.
    audit_sink_scope.reset();
    audit_sink_scope = std::make_unique<LocalDatabaseScope>(database);
    federation = std::move(other.federation);
    media_repository = std::move(other.media_repository);
    hardening = std::move(other.hardening);
    started = other.started;
    outbound_client = std::move(other.outbound_client);
    discovery_network = std::move(other.discovery_network);
    dispatch_worker = std::move(other.dispatch_worker);
    sync_notifier = std::exchange(other.sync_notifier, nullptr);
    typing_users = std::move(other.typing_users);
    receipts = std::move(other.receipts);
    return *this;
}

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
        if (membership.membership != "join")
        {
            continue;
        }
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

    // Repair state entries that older code failed to create for events with
    // state_key="" (m.room.create, m.room.join_rules, m.room.power_levels, …).
    // Without these entries build_pdu_auth_event_map cannot find the create event
    // and auth step 2 rejects every inbound federated PDU for the affected rooms.
    auto const repaired = database::repair_missing_state_entries(database.persistent_store);
    if (repaired > 0U)
    {
        LOG_WARNING(observability::diagnostic_log_summary(
            "runtime", "database.state.repaired", {{"count", std::to_string(repaired), false}}));
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
        log_diagnostic("start.rejected", {
                                             {"reason", "configuration is invalid", false}
        });
        return {false, "configuration is invalid", {}};
    }
    if (config.database().role != config::DatabaseRole::runtime)
    {
        log_diagnostic("start.rejected", {
                                             {"reason", "runtime requires database.role=runtime", false}
        });
        return {false, "runtime requires database.role=runtime", {}};
    }

    auto runtime = HomeserverRuntime{};
    runtime.config = config;
    runtime.listeners = net::make_runtime_listeners(config);
    if (runtime.listeners.empty())
    {
        log_diagnostic("start.rejected", {
                                             {"reason", "no runtime listeners configured", false}
        });
        return {false, "no runtime listeners configured", {}};
    }
    log_diagnostic("start.listeners_ready", {
                                                {"listener_count", std::to_string(runtime.listeners.count()), false}
    });

    runtime.database = bootstrap_local_database(config, std::move(existing_state));
    // The default ctor installed `audit_sink_scope` against the
    // empty `LocalDatabase{}` placeholder. Now that `database` holds
    // the real connection state, re-seat the scope so audit rows
    // route through the *current* `database` member (which is the
    // one the caller will see via NRVO in the returned
    // `RuntimeStartResult`).
    runtime.audit_sink_scope->reset(runtime.database);
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
        !database_has_table(runtime.database, "media_blobs") || !database_has_table(runtime.database, "remote_media") ||
        !database_has_table(runtime.database, "policy_rules") ||
        !database_has_table(runtime.database, "account_data") ||
        !database_has_table(runtime.database, "room_account_data") ||
        !database_has_table(runtime.database, "audit_log") || !database_has_table(runtime.database, "admin_actions"))
    {
        log_diagnostic("start.rejected",
                       {
                           {"opened",           runtime.database.opened ? "true" : "false",           false},
                           {"schema_validated", runtime.database.schema_validated ? "true" : "false", false},
                           {"reason",           "database schema validation failed",                  false}
        });
        return {false, "database schema validation failed", {}};
    }
    log_diagnostic("start.database_ready",
                   {
                       {"schema_version", std::to_string(runtime.database.schema_version), false},
                       {"table_count",    std::to_string(runtime.database.tables.size()),  false}
    });

    runtime.federation = federation::make_federation_runtime_state(federation::make_runtime_federation_config(config));
    runtime.outbound_client = std::make_unique<http::OutboundClient>();
    runtime.discovery_network = federation::make_system_server_discovery_network();
    runtime.media_repository = media::make_local_media_repository(media::make_runtime_media_config(config));
    hydrate_media_repository(runtime.media_repository, runtime.database.persistent_store);
    runtime.hardening = platform::run_startup_hardening_self_check();
    log_diagnostic("start.complete",
                   {
                       {"hardening_checks",      std::to_string(runtime.hardening.count()),             false},
                       {"hardening_alpha_ready", runtime.hardening.is_alpha_ready() ? "true" : "false", false},
                       {"federation_enabled",    runtime.federation.config.enabled ? "true" : "false",  false}
    });
    append_local_audit(runtime.database, observability::AuditCategory::admin, "runtime.started", "server", "homeserver",
                       "startup");
    runtime.started = true;

    // Pre-warm the key server response cache before the HTTP server starts accepting
    // connections. This ensures /_matrix/key/v2/server is served lock-free from the
    // very first request, even if make_join or another outbound operation arrives
    // concurrently on a different connection and holds the runtime mutex.
    auto const key_warm = publish_server_signing_keys(runtime);
    if (!key_warm.ok)
    {
        log_diagnostic("start.key_server_cache_warn",
                       {
                           {"reason", key_warm.reason.empty() ? "key unavailable" : key_warm.reason, false}
        });
    }

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

auto admin_audit_summary(HomeserverRuntime const& runtime, std::optional<observability::AuditCategory> category,
                         std::optional<std::string_view> event_type) -> std::string
{
    // Filter the audit log by the optional `category` and `event_type`
    // parameters. The result line is prefixed with the count of *all*
    // audit rows so the operator can see how many rows the filter
    // excluded; the per-entry lines only include the matching rows.
    auto const& log = runtime.database.persistent_store.audit_log;
    auto summary = std::string{"audit events="} + std::to_string(log.size());
    if (category.has_value())
    {
        summary += " filter_category=" + std::string{observability::audit_category_name(*category)};
    }
    if (event_type.has_value())
    {
        summary += " filter_event_type=" + std::string{*event_type};
    }
    for (auto const& event : log)
    {
        if (category.has_value() && event.category != observability::audit_category_name(*category))
        {
            continue;
        }
        if (event_type.has_value() && event.event_type != *event_type)
        {
            continue;
        }
        summary += " entry=" + event.category + ':' + event.event_type + ':' + event.actor + ':' + event.target + ':' +
                   event.reason;
    }
    return summary;
}

} // namespace merovingian::homeserver
