// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/config/config.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/federation/dispatch_worker.hpp"
#include "merovingian/federation/inbound_request.hpp"
#include "merovingian/federation/server_discovery.hpp"
#include "merovingian/http/outbound_client.hpp"
#include "merovingian/media/repository.hpp"
#include "merovingian/net/listener.hpp"
#include "merovingian/observability/observability.hpp"
#include "merovingian/platform/hardening_self_check.hpp"
#include "merovingian/sync/sync_notifier.hpp"

#include <cstdint>
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
};

struct LocalRoom final
{
    std::string room_id{};
    std::string creator_user_id{};
    std::vector<std::string> members{};
    std::vector<std::string> events{};
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
    std::vector<unsigned char> signing_secret_key{};
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
};

struct InboundReceipt final
{
    std::string room_id{};
    std::string receipt_type{"m.read"};
    std::string user_id{};
    std::string event_id{};
    std::uint64_t ts{0U};
};

struct HomeserverRuntime final
{
    HomeserverRuntime() = default;
    HomeserverRuntime(HomeserverRuntime const& other) = delete;
    auto operator=(HomeserverRuntime const& other) -> HomeserverRuntime& = delete;
    HomeserverRuntime(HomeserverRuntime&& other) noexcept;
    auto operator=(HomeserverRuntime&& other) noexcept -> HomeserverRuntime&;

    config::Config config{};
    net::RuntimeListeners listeners{};
    LocalDatabase database{};
    federation::FederationRuntimeState federation{};
    media::LocalMediaRepository media_repository{};
    platform::HardeningSelfCheck hardening{};
    bool started{false};
    std::unique_ptr<http::OutboundClient> outbound_client{};
    std::unique_ptr<federation::ServerDiscoveryNetwork> discovery_network{};
    std::unique_ptr<federation::DispatchWorker> dispatch_worker{};
    sync::SyncNotifier* sync_notifier{nullptr};
    std::vector<InboundTypingUser> typing_users{};
    std::vector<InboundReceipt> receipts{};
    // Guards mutable runtime state when requests are handled concurrently.
    // Handlers must release it before outbound network I/O so unrelated
    // requests can continue while a federation round-trip is in flight.
    mutable std::recursive_mutex mutex{};
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
[[nodiscard]] auto admin_health(HomeserverRuntime const& runtime) -> observability::HealthCheckSnapshot;
[[nodiscard]] auto admin_health_summary(HomeserverRuntime const& runtime) -> std::string;
[[nodiscard]] auto admin_metrics_summary(HomeserverRuntime const& runtime) -> std::string;
[[nodiscard]] auto admin_audit_summary(HomeserverRuntime const& runtime,
                                    std::optional<observability::AuditCategory> category = std::nullopt,
                                    std::optional<std::string_view> event_type = std::nullopt) -> std::string;
auto apply_runtime_membership(LocalDatabase& database, std::string_view room_id, std::string_view user_id,
                              std::string_view membership) -> void;

} // namespace merovingian::homeserver
