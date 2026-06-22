// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/config/config.hpp"
#include "merovingian/core/secret_buffer.hpp"
#include "merovingian/database/persistent_store.hpp"
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
    // Moment after which this typing indicator is considered stale.  Defaults
    // to the distant future so test fixtures and legacy entries that never set
    // a timeout remain visible until explicitly cleared.
    std::chrono::steady_clock::time_point expires_at{std::chrono::steady_clock::time_point::max()};
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
    std::unique_ptr<federation::DispatchWorker> dispatch_worker{};
    sync::SyncNotifier* sync_notifier{nullptr};
    std::vector<InboundTypingUser> typing_users{};
    std::vector<InboundReceipt> receipts{};
    // Per-connection MSC4186 sliding sync state.
    // Key: user_id + "/" + device_id + "/" + conn_id (or "__default__").
    std::map<std::string, sync::SlidingSyncConnectionState> sliding_sync_connections{};
    std::uint64_t next_request_sequence{1U};
    // Guards mutable runtime state when requests are handled concurrently.
    // Handlers must release it before outbound network I/O so unrelated
    // requests can continue while a federation round-trip is in flight.
    mutable std::recursive_mutex mutex{};
};

// Default timeout applied to inbound federation typing EDUs, which do not
// carry a client-supplied timeout.  30 s matches common client refresh
// intervals and prevents remote typing indicators from sticking forever.
[[nodiscard]] constexpr auto federation_typing_timeout() noexcept -> std::chrono::milliseconds
{
    return std::chrono::milliseconds{30'000};
}

// Scan in-memory typing rows and mark any whose expiry has passed as no
// longer typing, bumping their sync stream id so the next /sync or sliding
// sync response can emit an updated (possibly empty) m.typing user list.
// Returns true if any row was reaped.  Callers must hold runtime.mutex.
[[nodiscard]] auto reap_expired_typing(
    HomeserverRuntime& runtime,
    std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now()) -> bool;

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
