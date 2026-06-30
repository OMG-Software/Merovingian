// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/runtime.hpp"

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/crypto/ed25519.hpp"
#include "merovingian/database/postgresql_store.hpp"
#include "merovingian/database/schema.hpp"
#include "merovingian/federation/runtime_federation.hpp"
#include "merovingian/homeserver/federation_proxy.hpp"
#include "merovingian/homeserver/local_services.hpp"
#include "merovingian/homeserver/room_service.hpp"
#include "merovingian/media/repository.hpp"
#include "merovingian/media/runtime_media.hpp"
#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"
#include "merovingian/platform/hardening_self_check.hpp"
#include "merovingian/platform/runtime_hardening.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdlib>
#include <fstream>
#include <memory>
#include <optional>
#include <ranges>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include <sodium.h>

namespace merovingian::homeserver
{
namespace
{

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields,
                        observability::LogEventSeverity severity = observability::LogEventSeverity::debug) -> void
    {
        observability::log_diagnostic("runtime", event, std::move(fields), severity);
    }

    // Production Ed25519 provider backed by the runtime signing secret.
    // The secret is copied once from the mlocked SecretBuffer into this object
    // when the runtime starts (or after key rotation) and held for the lifetime
    // of the runtime so that signing operations do not repeatedly copy the key.
    class RuntimeEd25519Provider final : public crypto::Ed25519Provider
    {
    public:
        explicit RuntimeEd25519Provider(std::array<unsigned char, crypto_sign_SECRETKEYBYTES> secret_key)
            : secret_key_{std::move(secret_key)}
        {
        }

        [[nodiscard]] auto sign(crypto::Ed25519SecretKeyHandle const& /*key*/, std::string_view message)
            -> crypto::SignatureResult override
        {
            auto signature = std::string(crypto_sign_BYTES, '\0');
            if (crypto_sign_detached(reinterpret_cast<unsigned char*>(signature.data()), nullptr,
                                     reinterpret_cast<unsigned char const*>(message.data()), message.size(),
                                     secret_key_.data()) != 0)
            {
                return {{}, "Ed25519 signing failed"};
            }
            return {crypto::Ed25519Signature{std::move(signature)}, {}};
        }

        [[nodiscard]] auto verify(crypto::Ed25519PublicKey const& public_key, std::string_view message,
                                  crypto::Ed25519Signature const& signature) -> crypto::VerificationResult override
        {
            if (!crypto::ed25519_public_key_shape_is_valid(public_key) ||
                !crypto::ed25519_signature_shape_is_valid(signature))
            {
                return {false, "invalid Ed25519 material"};
            }
            auto const ok =
                crypto_sign_verify_detached(reinterpret_cast<unsigned char const*>(signature.bytes.data()),
                                            reinterpret_cast<unsigned char const*>(message.data()), message.size(),
                                            reinterpret_cast<unsigned char const*>(public_key.bytes.data())) == 0;
            return {ok, ok ? std::string{} : std::string{"signature verification failed"}};
        }

    private:
        std::array<unsigned char, crypto_sign_SECRETKEYBYTES> secret_key_{};
    };

    [[nodiscard]] auto make_metric(std::string name, std::int64_t value, observability::MetricType type,
                                   std::string help, std::vector<observability::MetricLabel> labels = {})
        -> observability::MetricSample
    {
        return {std::move(name), value, true, type, std::move(help), std::move(labels)};
    }

    [[nodiscard]] auto admin_metrics(HomeserverRuntime const& runtime) -> std::vector<observability::MetricSample>
    {
        auto const& store = runtime.database.persistent_store;
        auto metrics = std::vector<observability::MetricSample>{
            make_metric("merovingian_server_identity", 1, observability::MetricType::gauge,
                        "Identity labels for the running homeserver process.",
                        {{"server_name", runtime.config.server().server_name, true}}
                        ),
            make_metric("merovingian_runtime_started", runtime.started ? 1 : 0, observability::MetricType::gauge,
                        "Whether the homeserver runtime has completed startup."),
            make_metric("merovingian_database_schema_version",
                        static_cast<std::int64_t>(runtime.database.schema_version), observability::MetricType::gauge,
                        "Current validated database schema version."),
            make_metric("users_total", static_cast<std::int64_t>(store.users.size()), observability::MetricType::gauge,
                        "Number of local users currently present in the persistent store."),
            make_metric("sessions_total", static_cast<std::int64_t>(store.access_tokens.size()),
                        observability::MetricType::gauge,
                        "Number of persisted access-token sessions currently known to the runtime."),
            make_metric("rooms_total", static_cast<std::int64_t>(store.rooms.size()), observability::MetricType::gauge,
                        "Number of persisted rooms currently known to the runtime."),
            make_metric("events_total", static_cast<std::int64_t>(store.events.size()),
                        observability::MetricType::gauge, "Number of persisted events currently known to the runtime."),
            make_metric("audit_events_appended_total", static_cast<std::int64_t>(store.audit_log.size()),
                        observability::MetricType::counter,
                        "Total number of durable audit events appended since the current store was created."),
            make_metric("admin_actions_total", static_cast<std::int64_t>(store.admin_actions.size()),
                        observability::MetricType::counter,
                        "Total number of durable admin actions appended since the current store was created."),
        };

        auto const health = admin_health(runtime);
        for (auto const& component : health.components)
        {
            metrics.push_back(make_metric("merovingian_health_status",
                                          component.status == observability::HealthStatus::ok
                                              ? 1
                                              : (component.status == observability::HealthStatus::degraded ? 0 : -1),
                                          observability::MetricType::gauge,
                                          "Current status of a named runtime health component.",
                                          {
                                              {"component", component.name,                                      true},
                                              {"status",    observability::health_status_name(component.status), true}
            }));
        }

        auto const media_metrics = media::media_repository_metrics(runtime.media_repository);
        metrics.insert(metrics.end(), media_metrics.begin(), media_metrics.end());
        return metrics;
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

    [[nodiscard]] auto object_member(canonicaljson::Object const& object, std::string_view key) noexcept
        -> canonicaljson::Value const*
    {
        for (auto const& member : object)
        {
            if (member.key == key)
            {
                return member.value.get();
            }
        }
        return nullptr;
    }

    [[nodiscard]] auto string_member(canonicaljson::Object const& object, std::string_view key) noexcept
        -> std::string const*
    {
        auto const* value = object_member(object, key);
        return value == nullptr ? nullptr : std::get_if<std::string>(&value->storage());
    }

    [[nodiscard]] auto parse_policy_server_action(std::string_view value) noexcept
        -> std::optional<trust_safety::PolicyAction>
    {
        using trust_safety::PolicyAction;
        if (value == "allow")
        {
            return PolicyAction::allow;
        }
        if (value == "deny")
        {
            return PolicyAction::deny;
        }
        if (value == "quarantine")
        {
            return PolicyAction::quarantine;
        }
        if (value == "lock_account")
        {
            return PolicyAction::lock_account;
        }
        if (value == "suspend_account")
        {
            return PolicyAction::suspend_account;
        }
        return std::nullopt;
    }

    [[nodiscard]] auto parse_policy_server_response(std::string_view body, trust_safety::PolicyServerHook hook)
        -> trust_safety::PolicyServerHook
    {
        if (body.empty())
        {
            return hook;
        }
        auto const parsed = canonicaljson::parse_lossless(body);
        if (parsed.error != canonicaljson::ParseError::none)
        {
            return hook;
        }
        auto const* object = std::get_if<canonicaljson::Object>(&parsed.value.storage());
        if (object == nullptr)
        {
            return hook;
        }

        auto const* action = string_member(*object, "action");
        if (action == nullptr)
        {
            return hook;
        }
        auto const parsed_action = parse_policy_server_action(*action);
        if (!parsed_action.has_value())
        {
            return hook;
        }

        hook.decision_received = true;
        hook.action = *parsed_action;
        if (auto const* rule_id = string_member(*object, "rule_id"); rule_id != nullptr)
        {
            hook.rule_id = *rule_id;
        }
        auto code = std::string{"policy_server_"};
        code += *action;
        auto summary = std::string{"policy server decision"};
        if (auto const* response_summary = string_member(*object, "summary");
            response_summary != nullptr && !response_summary->empty())
        {
            summary = *response_summary;
        }
        auto detail = summary;
        if (auto const* response_reason = string_member(*object, "reason"); response_reason != nullptr)
        {
            detail = *response_reason;
        }
        hook.reason = trust_safety::enforcement_reason(code, summary, detail);
        return hook;
    }

} // namespace

// Rebuilds crypto_provider_owned from runtime.database.signing_secret_key.
// Called after startup and after every key rotation so the active provider
// always matches the currently persisted key. Exposed to room_service.cpp for
// use by rotate_server_signing_key.
auto reset_runtime_crypto_provider(HomeserverRuntime& runtime) -> void
{
    if (runtime.database.signing_secret_key.bytes().size() == crypto_sign_SECRETKEYBYTES)
    {
        auto secret_key = std::array<unsigned char, crypto_sign_SECRETKEYBYTES>{};
        std::copy(runtime.database.signing_secret_key.bytes().begin(),
                  runtime.database.signing_secret_key.bytes().end(), secret_key.begin());
        runtime.crypto_provider_owned = std::make_unique<RuntimeEd25519Provider>(std::move(secret_key));
        runtime.crypto_provider = runtime.crypto_provider_owned.get();
    }
    else
    {
        runtime.crypto_provider_owned.reset();
        runtime.crypto_provider = nullptr;
    }
}

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
    , trust_safety_policy_server(std::move(other.trust_safety_policy_server))
    , discovery_network(std::move(other.discovery_network))
    , dispatch_worker(std::move(other.dispatch_worker))
    , federation_proxy(std::move(other.federation_proxy))
    , crypto_provider_owned(std::move(other.crypto_provider_owned))
    , crypto_provider(other.crypto_provider)
    , sync_notifier(std::exchange(other.sync_notifier, nullptr))
    , typing_users(std::move(other.typing_users))
    , receipts(std::move(other.receipts))
    , room_typing_stream_id(std::move(other.room_typing_stream_id))
{
    other.crypto_provider = nullptr;
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
    trust_safety_policy_server = std::move(other.trust_safety_policy_server);
    discovery_network = std::move(other.discovery_network);
    dispatch_worker = std::move(other.dispatch_worker);
    federation_proxy = std::move(other.federation_proxy);
    crypto_provider_owned = std::move(other.crypto_provider_owned);
    crypto_provider = other.crypto_provider;
    other.crypto_provider = nullptr;
    sync_notifier = std::exchange(other.sync_notifier, nullptr);
    typing_users = std::move(other.typing_users);
    receipts = std::move(other.receipts);
    room_typing_stream_id = std::move(other.room_typing_stream_id);
    return *this;
}

[[nodiscard]] auto current_typing_users_in_room(HomeserverRuntime const& rt, std::string_view room_id)
    -> std::vector<std::string>
{
    auto users = std::vector<std::string>{};
    for (auto const& entry : rt.typing_users)
    {
        if (entry.room_id == room_id && entry.typing)
        {
            users.push_back(entry.user_id);
        }
    }
    std::ranges::sort(users);
    return users;
}

[[nodiscard]] auto room_typing_stream_id_for(HomeserverRuntime const& rt, std::string_view room_id) -> std::uint64_t
{
    auto const it = rt.room_typing_stream_id.find(std::string{room_id});
    return it == rt.room_typing_stream_id.end() ? std::uint64_t{0U} : it->second;
}

[[nodiscard]] auto update_room_typing_stream_id_if_changed(HomeserverRuntime& rt, std::string_view room_id,
                                                           std::vector<std::string> const& previous) -> std::uint64_t
{
    auto const current = current_typing_users_in_room(rt, room_id);
    if (previous == current)
    {
        return room_typing_stream_id_for(rt, room_id);
    }
    auto const new_id = database::allocate_sync_stream_id(rt.database.persistent_store);
    rt.room_typing_stream_id[std::string{room_id}] = new_id;
    return new_id;
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

    log_diagnostic("database.hydrated",
                   {
                       {"rooms_total",       std::to_string(database.rooms.size()),                         false},
                       {"memberships_total", std::to_string(database.persistent_store.memberships.size()),  false},
                       {"users_total",       std::to_string(database.users.size()),                         false},
                       {"sessions_total",    std::to_string(database.sessions.size()),                      false},
                       {"events_total",      std::to_string(database.persistent_store.events.size()),       false},
                       {"sync_stream_id",    std::to_string(database.persistent_store.next_sync_stream_id), false}
    },
                   observability::LogEventSeverity::info);

    // Repair state entries that older code failed to create for events with
    // state_key="" (m.room.create, m.room.join_rules, m.room.power_levels, …).
    // Without these entries build_pdu_auth_event_map cannot find the create event
    // and auth step 2 rejects every inbound federated PDU for the affected rooms.
    auto const repaired = database::repair_missing_state_entries(database.persistent_store);
    if (repaired > 0U)
    {
        log_diagnostic("database.state.repaired",
                       {
                           {"count", std::to_string(repaired), false}
        },
                       observability::LogEventSeverity::warning);
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
    return start_runtime(RuntimeStartOptions{.config = config});
}

auto start_runtime(config::Config const& config, database::SchemaState existing_state) -> RuntimeStartResult
{
    return start_runtime(RuntimeStartOptions{.config = config, .existing_state = std::move(existing_state)});
}

auto start_runtime(RuntimeStartOptions opts) -> RuntimeStartResult
{
    auto const& config = opts.config;
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
    log_diagnostic("start.listeners_ready",
                   {
                       {"listener_count", std::to_string(runtime.listeners.count()), false}
    },
                   observability::LogEventSeverity::info);

    runtime.database = bootstrap_local_database(config, std::move(opts.existing_state));
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
    },
                   observability::LogEventSeverity::info);

    // Wire the signing provider. The main process loads the persisted signing secret;
    // the federation worker receives an IPC-backed override so the secret never enters
    // the child process. The provider must be ready before publish_server_signing_keys
    // or any federation handler runs.
    if (opts.signing_override != nullptr)
    {
        runtime.crypto_provider = opts.signing_override;
        log_diagnostic("start.crypto_provider_override",
                       {
                           {"reason", "IPC-backed signing provider", false}
        },
                       observability::LogEventSeverity::info);
    }
    else
    {
        std::ignore = ensure_runtime_server_signing_key(runtime);
        reset_runtime_crypto_provider(runtime);
        log_diagnostic("start.crypto_provider_ready",
                       {
                           {"available", runtime.crypto_provider != nullptr ? "true" : "false", false}
        },
                       observability::LogEventSeverity::info);
    }

    runtime.federation = federation::make_federation_runtime_state(federation::make_runtime_federation_config(config));
    runtime.outbound_client = std::make_unique<http::OutboundClient>();
    runtime.discovery_network = federation::make_system_server_discovery_network();
    runtime.media_repository = media::make_local_media_repository(media::make_runtime_media_config(config));
    hydrate_media_repository(runtime.media_repository, runtime.database.persistent_store);
    // Tests run in a long-lived Catch2 process. Applying seccomp/pledge/unveil
    // there would permanently restrict that process and break every subsequent
    // test. The build scripts set MEROVINGIAN_TEST_DISABLE_HARDENING=1 when they
    // invoke the test suite; production binaries never see it.
    auto const hardening_controls = [&]() {
        if (std::getenv("MEROVINGIAN_TEST_DISABLE_HARDENING") != nullptr)
        {
            log_diagnostic(
                "hardening.test_disable",
                {
                    {
                     "reason", std::string{"runtime hardening controls disabled by MEROVINGIAN_TEST_DISABLE_HARDENING"},
                     false, }
            },
                observability::LogEventSeverity::info);
            return platform::HardeningPlanDecision{true, false, "disabled by MEROVINGIAN_TEST_DISABLE_HARDENING"};
        }
#if defined(__linux__)
        return platform::apply_runtime_hardening_controls(platform::default_linux_hardening_profile());
#elif defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__DragonFly__)
        return platform::apply_runtime_hardening_controls(platform::default_bsd_hardening_profile());
#else
        return platform::apply_runtime_hardening_controls(platform::default_portable_hardening_profile());
#endif
    }();
    log_diagnostic("start.hardening_controls",
                   {
                       {"accepted", hardening_controls.accepted ? "true" : "false", false},
                       {"reason",   hardening_controls.reason,                      false},
    },
                   observability::LogEventSeverity::info);
    // Capture a hardening self-check snapshot for the health endpoint. The final
    // startup gate in main.cpp re-runs the check after all platform controls are
    // applied and overwrites runtime.hardening with the definitive result.
    runtime.hardening = platform::run_startup_hardening_self_check();
    log_diagnostic("start.complete",
                   {
                       {"federation_enabled", runtime.federation.config.enabled ? "true" : "false", false}
    },
                   observability::LogEventSeverity::info);
    append_local_audit(runtime.database, observability::AuditCategory::admin, "runtime.started", "server", "homeserver",
                       "startup");
    runtime.started = true;

    // Pre-warm the key server response cache before the HTTP server starts accepting
    // connections. This ensures /_matrix/key/v2/server is served lock-free from the
    // very first request, even if make_join or another outbound operation arrives
    // concurrently on a different connection and holds the runtime mutex.
    // The federation worker does not serve /_matrix/key/v2/server and has no local
    // signing secret, so skip the pre-warm when running with an external provider.
    if (opts.signing_override == nullptr)
    {
        auto const key_warm = publish_server_signing_keys(runtime);
        if (!key_warm.ok)
        {
            log_diagnostic("start.key_server_cache_warn",
                           {
                               {"reason", key_warm.reason.empty() ? "key unavailable" : key_warm.reason, false}
            });
        }
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
    return observability::prometheus_metrics_summary(admin_metrics(runtime));
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

auto find_policy_rule(HomeserverRuntime const& runtime, std::string_view scope, std::string_view entity)
    -> std::optional<database::PersistentPolicyRule>
{
    auto const& rules = runtime.database.persistent_store.policy_rules;
    auto const exact = std::ranges::find_if(rules, [scope, entity](database::PersistentPolicyRule const& rule) {
        return rule.scope == scope && rule.entity == entity;
    });
    if (exact != rules.end())
    {
        return *exact;
    }
    auto const wildcard = std::ranges::find_if(rules, [scope](database::PersistentPolicyRule const& rule) {
        return rule.scope == scope && rule.entity == "*";
    });
    return wildcard == rules.end() ? std::nullopt : std::optional<database::PersistentPolicyRule>{*wildcard};
}

auto resolve_policy_server_hook(HomeserverRuntime& runtime, trust_safety::PolicySurface surface,
                                std::string_view entity) -> trust_safety::PolicyServerHook
{
    auto const& trust_safety_config = runtime.config.security().trust_safety;
    if (!trust_safety_config.enabled || trust_safety_config.policy_server_url.empty())
    {
        return {};
    }

    auto hook = trust_safety::PolicyServerHook{};
    hook.enabled = true;
    hook.reachable = false;
    hook.allow_without_result = trust_safety_config.policy_server_allow_without_result;
    auto const timeout = config::parse_duration_seconds(trust_safety_config.policy_server_timeout);
    hook.timeout_milliseconds = timeout.valid ? timeout.seconds * 1000U : 0U;

    if (runtime.trust_safety_policy_server)
    {
        return runtime.trust_safety_policy_server(surface, entity);
    }

    if (runtime.outbound_client == nullptr || hook.timeout_milliseconds == 0U)
    {
        return hook;
    }

    auto payload = canonicaljson::Object{};
    payload.push_back(canonicaljson::make_member(
        "surface", canonicaljson::Value{std::string{trust_safety::policy_surface_name(surface)}}));
    payload.push_back(canonicaljson::make_member("entity", canonicaljson::Value{std::string{entity}}));
    payload.push_back(
        canonicaljson::make_member("server_name", canonicaljson::Value{runtime.config.server().server_name}));
    auto const serialized = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(payload)});
    if (serialized.error != canonicaljson::CanonicalJsonError::none)
    {
        return hook;
    }

    auto request = http::OutboundRequest{};
    request.method = "POST";
    request.url = trust_safety_config.policy_server_url;
    request.connect_timeout_seconds = timeout.valid ? timeout.seconds : 0U;
    request.total_timeout_seconds = timeout.valid ? timeout.seconds : 0U;
    request.headers = {
        {"Content-Type", "application/json"}
    };
    request.body = serialized.output;
    auto const result = runtime.outbound_client->perform(request);
    if (!result.ok)
    {
        return hook;
    }
    if (result.response.status < 200U || result.response.status >= 300U)
    {
        hook.reachable = true;
        return hook;
    }

    hook.reachable = true;
    return parse_policy_server_response(result.response.body, std::move(hook));
}

} // namespace merovingian::homeserver
