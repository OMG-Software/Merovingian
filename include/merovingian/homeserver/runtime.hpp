// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/config/config.hpp"
#include "merovingian/core/secret_buffer.hpp"
#include "merovingian/crypto/ed25519.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/federation/cached_server_discovery.hpp"
#include "merovingian/federation/dispatch_worker.hpp"
#include "merovingian/federation/inbound_request.hpp"
#include "merovingian/federation/server_discovery.hpp"
#include "merovingian/http/outbound_client.hpp"
#include "merovingian/media/repository.hpp"
#include "merovingian/net/listener.hpp"
#include "merovingian/observability/observability.hpp"
#include "merovingian/platform/hardening_self_check.hpp"
#include "merovingian/sync/sliding_sync.hpp"
#include "merovingian/sync/sync_notifier.hpp"
#include "merovingian/trust_safety/policy_engine.hpp"

#include <chrono>
#include <cstdint>
#include <functional>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace merovingian::homeserver
{

// Forward declaration — full type in federation_proxy.hpp, included by runtime.cpp.
class FederationProxy;

// Thread-safe cache for the signed /_matrix/key/v2/server response.
// Uses its own mutex so the response can be served without holding the
// global runtime mutex — Synapse's ServerKeyFetcher times out (~20 s)
// if a concurrent make_join round-trip holds the lock for too long.
// Wrapped in unique_ptr by callers so containing structs stay moveable.
struct KeyServerCache final
{
    // Returns the cached response, or nullopt if the cache is empty.
    [[nodiscard]] auto load() const -> std::optional<std::string>
    {
        auto const lk = std::lock_guard{mutex_};
        if (value_.empty())
        {
            return std::nullopt;
        }
        return value_;
    }

    // Atomically replaces the cached response.
    auto store(std::string value) -> void
    {
        auto const lk = std::lock_guard{mutex_};
        value_ = std::move(value);
    }

private:
    mutable std::mutex mutex_{};
    std::string value_{};
};

struct LocalUser final
{
    std::string user_id{};
    std::string password_hash{};
    bool locked{false};
    bool suspended{false};
    bool admin{false};
};

struct LocalSession final
{
    std::string user_id{};
    std::string device_id{};
    std::string access_token_hash{};
    bool revoked{false};
    // Server-side access-token expiry mirrored from PersistentAccessToken. nullopt
    // = no expiry. find_session rejects an expired session even when not revoked.
    std::optional<std::chrono::system_clock::time_point> expires_at{};
};

struct LocalRoom final
{
    std::string room_id{};
    std::string creator_user_id{};
    std::vector<std::string> members{};
    std::vector<std::string> events{};
    // True when the room has been explicitly published to the public room directory
    // via PUT /_matrix/client/v3/directory/list/room/{roomId}. Private by default.
    bool directory_public{false};
};

struct LocalDatabase final
{
    bool opened{false};
    bool schema_validated{false};
    std::uint32_t schema_version{0U};
    std::uint64_t next_session_id{1U};
    std::uint64_t next_event_id{1U};
    std::vector<std::string> tables{};
    std::vector<LocalUser> users{};
    std::vector<LocalSession> sessions{};
    std::vector<LocalRoom> rooms{};
    std::vector<observability::AuditLogEvent> audit_events{};
    database::PersistentStore persistent_store{};
    core::SecretBuffer signing_secret_key{};
    // Cache of the signed /_matrix/key/v2/server response, protected by its own
    // internal mutex so the federation key endpoint can be served without acquiring
    // the global runtime mutex. Wrapped in unique_ptr so LocalDatabase remains
    // move-constructible (std::mutex is not moveable).
    std::unique_ptr<KeyServerCache> key_server_cache{std::make_unique<KeyServerCache>()};
    std::uint64_t next_stream_ordering{1U};
};

struct InboundTypingUser final
{
    std::string room_id{};
    std::string user_id{};
    bool typing{false};
    std::uint64_t stream_id{0U};
};

struct InboundReceipt final
{
    std::string room_id{};
    std::string receipt_type{"m.read"};
    std::string user_id{};
    std::string event_id{};
    std::uint64_t ts{0U};
    std::uint64_t stream_id{0U};
};

// RAII scope guard that wires the active `LocalDatabase` into the
// audit sink on construction and *clears* the install on destruction
// (if the install still belongs to this scope). The full definition
// lives in `merovingian/homeserver/local_services.hpp`; the
// forward-declaration here lets `HomeserverRuntime` own one as a
// pimpl-typed member without dragging the audit-sink functions into
// this header. See the class definition for the full contract.
class LocalDatabaseScope;

struct HomeserverRuntime final
{
    HomeserverRuntime();
    HomeserverRuntime(HomeserverRuntime const& other) = delete;
    auto operator=(HomeserverRuntime const& other) -> HomeserverRuntime& = delete;
    HomeserverRuntime(HomeserverRuntime&& other) noexcept;
    auto operator=(HomeserverRuntime&& other) noexcept -> HomeserverRuntime&;
    ~HomeserverRuntime();

    config::Config config{};
    net::RuntimeListeners listeners{};
    LocalDatabase database{};
    // RAII scope guard that binds the audit-sink install to this
    // runtime's lifetime. Constructed in the runtime ctor against
    // `database` and cleared in the dtor; if a different runtime
    // takes over the install (e.g. via move), the source's scope
    // detects the mismatch and becomes a no-op on its own dtor.
    // `std::unique_ptr` keeps the runtime movable without requiring
    // `LocalDatabaseScope` to be a complete type in this header.
    std::unique_ptr<LocalDatabaseScope> audit_sink_scope{};
    federation::FederationRuntimeState federation{};
    media::LocalMediaRepository media_repository{};
    platform::HardeningSelfCheck hardening{};
    bool started{false};
    std::unique_ptr<http::OutboundClient> outbound_client{};
    std::function<trust_safety::PolicyServerHook(trust_safety::PolicySurface, std::string_view)>
        trust_safety_policy_server{};
    std::unique_ptr<federation::ServerDiscoveryNetwork> discovery_network{};
    // TTL-bounded cache wrapping `discovery_network`. Non-null in the main
    // process after start_runtime; null in the federation worker and in test
    // harnesses that wire only the raw network. Callers MUST prefer this over
    // `discovery_network` so repeated lookups skip the DNS cascade.
    std::unique_ptr<federation::CachedServerDiscovery> cached_discovery{};
    std::unique_ptr<federation::DispatchWorker> dispatch_worker{};
    // Non-null when federation.worker.enabled = true. Intercepts inbound
    // federation requests and forwards them to the out-of-process worker.
    std::unique_ptr<FederationProxy> federation_proxy{};
    // Owned implementation of the runtime signing provider. Null when an
    // external provider (e.g. IpcEd25519Provider in the federation worker)
    // is supplied via RuntimeStartOptions::signing_override.
    std::unique_ptr<crypto::Ed25519Provider> crypto_provider_owned{};
    // Active Ed25519 provider used for server signing. Points to
    // crypto_provider_owned for the main process and to the override in
    // worker contexts. Check for nullptr before signing.
    crypto::Ed25519Provider* crypto_provider{nullptr};
    sync::SyncNotifier* sync_notifier{nullptr};
    std::vector<InboundTypingUser> typing_users{};
    std::vector<InboundReceipt> receipts{};
    // Per-room monotonic cursor advanced whenever the set of typing users in
    // the room changes.  Used by /sync and MSC4186 typing extensions to emit
    // the current (possibly empty) typing list on every change.
    std::map<std::string, std::uint64_t> room_typing_stream_id{};
    // Per-connection MSC4186 sliding sync state.
    // Key: user_id + "/" + device_id + "/" + conn_id (or "__default__").
    std::map<std::string, sync::SlidingSyncConnectionState> sliding_sync_connections{};
    std::uint64_t next_request_sequence{1U};
    // Guards mutable runtime state when requests are handled concurrently.
    // Handlers must release it before outbound network I/O so unrelated
    // requests can continue while a federation round-trip is in flight.
    mutable std::recursive_mutex mutex{};
    // Loser futures from the parallel make_join race (see race_make_join_candidates
    // in room_service.cpp). When the race finds a winner it returns immediately;
    // the still-running loser tasks (in-flight outbound make_join calls that
    // cannot be cancelled) are moved here so the caller does not block on them.
    // They are drained (removed once ready) at the start of the next race and
    // waited on at runtime destruction. Declared LAST so it is destroyed FIRST:
    // the dtor joins the loser tasks while outbound_client/discovery_network
    // (declared earlier) are still alive, and the tasks' captured `&runtime`
    // reference stays valid throughout the drain. Moves only happen at startup
    // (before any race creates orphans), so the vector is empty at move time.
    std::mutex orphan_futures_mutex_{};
    std::vector<std::future<void>> orphan_futures_{};
};

// Typing-state helpers used by client-server and federation handlers.
[[nodiscard]] auto current_typing_users_in_room(HomeserverRuntime const& rt, std::string_view room_id)
    -> std::vector<std::string>;
[[nodiscard]] auto room_typing_stream_id_for(HomeserverRuntime const& rt, std::string_view room_id) -> std::uint64_t;
[[nodiscard]] auto update_room_typing_stream_id_if_changed(HomeserverRuntime& rt, std::string_view room_id,
                                                           std::vector<std::string> const& previous) -> std::uint64_t;

struct RuntimeStartOptions final
{
    config::Config config{};
    database::SchemaState existing_state{};
    // Non-owning pointer to an Ed25519Provider to use instead of loading the
    // server signing secret into this runtime. Used by the federation worker
    // to delegate signing to the main process over IPC.
    crypto::Ed25519Provider* signing_override{nullptr};
};

struct RuntimeStartResult final
{
    bool started{false};
    std::string reason{};
    HomeserverRuntime runtime{};
};

struct OperationResult final
{
    bool ok{false};
    std::uint16_t status{500U};
    std::string value{};
    std::string reason{};
};

struct SessionRefreshResult final
{
    bool ok{false};
    std::uint16_t status{500U};
    std::string access_token{};
    std::string refresh_token{};
    std::string user_id{};
    std::string device_id{};
    std::string reason{};
};

[[nodiscard]] auto bootstrap_local_database(config::Config const& config) -> LocalDatabase;
[[nodiscard]] auto bootstrap_local_database(config::Config const& config, database::SchemaState existing_state)
    -> LocalDatabase;
[[nodiscard]] auto database_has_table(LocalDatabase const& database, std::string_view table_name) noexcept -> bool;
[[nodiscard]] auto start_runtime(config::Config const& config) -> RuntimeStartResult;
[[nodiscard]] auto start_runtime(config::Config const& config, database::SchemaState existing_state)
    -> RuntimeStartResult;
[[nodiscard]] auto start_runtime(RuntimeStartOptions opts) -> RuntimeStartResult;
// Re-creates the runtime's owned signing provider from runtime.database.signing_secret_key.
// Called by start_runtime after the signing key is ensured and by rotate_server_signing_key
// after a rotation. This is a no-op when an external provider override is active.
auto reset_runtime_crypto_provider(HomeserverRuntime& runtime) -> void;
[[nodiscard]] auto admin_health(HomeserverRuntime const& runtime) -> observability::HealthCheckSnapshot;
[[nodiscard]] auto admin_health_summary(HomeserverRuntime const& runtime) -> std::string;
[[nodiscard]] auto admin_metrics_summary(HomeserverRuntime const& runtime) -> std::string;
[[nodiscard]] auto admin_audit_summary(HomeserverRuntime const& runtime,
                                       std::optional<observability::AuditCategory> category = std::nullopt,
                                       std::optional<std::string_view> event_type = std::nullopt) -> std::string;
[[nodiscard]] auto find_policy_rule(HomeserverRuntime const& runtime, std::string_view scope, std::string_view entity)
    -> std::optional<database::PersistentPolicyRule>;
[[nodiscard]] auto resolve_policy_server_hook(HomeserverRuntime& runtime, trust_safety::PolicySurface surface,
                                              std::string_view entity) -> trust_safety::PolicyServerHook;
auto apply_runtime_membership(LocalDatabase& database, std::string_view room_id, std::string_view user_id,
                              std::string_view membership) -> void;

} // namespace merovingian::homeserver
