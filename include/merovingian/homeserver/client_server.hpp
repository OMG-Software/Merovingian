// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/dispatch_result.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/http/rate_limit.hpp"
#include "merovingian/sync/sync_notifier.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::homeserver
{

struct ClientDevice final
{
    std::string user_id{};
    std::string device_id{};
    std::string display_name{};
};

struct ClientKeyApiRecord final
{
    std::string user_id{};
    std::string device_id{};
    std::string endpoint{};
    std::string payload_summary{};
    std::size_t statement_count{0U};
};

struct RegistrationValidationSession final
{
    std::string sid{};
    std::string medium{};
    std::string address{};
    std::string client_secret{};
    std::string client_ip{};
    std::optional<std::string> country{};
    std::optional<std::string> next_link{};
    std::uint64_t send_attempt{0U};
    std::uint64_t created_at_ms{0U};
    std::uint64_t updated_at_ms{0U};
};

struct ClientApiLimits final
{
    // 64 KiB covers real Matrix API calls including keys/upload (device keys +
    // many one-time keys) while staying well below the HTTP-layer 1 MiB cap in
    // http::RequestLimits::max_body_bytes.
    std::size_t max_body_bytes{65536U};
    std::size_t max_sync_rooms{16U};
    std::size_t max_sync_events_per_room{8U};
};

// Wall-clock source for the rate-limit engine. The engine takes a
// callable; we hold the state inline so the engine (a unique_ptr) can
// borrow it. Default-constructed runtimes start at steady_clock origin.
struct ClientServerClock final
{
    [[nodiscard]] auto operator()() const noexcept -> std::chrono::steady_clock::time_point
    {
        return std::chrono::steady_clock::now();
    }
};

struct ClientServerRuntime final
{
    HomeserverRuntime homeserver{};
    ClientApiLimits limits{};
    std::vector<ClientDevice> devices{};
    std::vector<ClientKeyApiRecord> key_api_records{};
    std::vector<RegistrationValidationSession> registration_validation_sessions{};
    // CORS policy snapshot. Copied from `config.server().cors` at
    // `start_client_server()` time. CORS is not hot-reloadable: a config
    // change requires a server restart.
    config::CorsConfig cors{};
    // Wall-clock rate-limit engine. Constructed once in
    // `start_client_server()` from `config.client_rate_limits()`. The
    // engine borrows `clock` (a member of the runtime) so the
    // unique_ptr can hold the templated engine and the runtime stays
    // movable. In tests the same engine template accepts a manual
    // clock via the same borrowed reference.
    ClientServerClock clock{};
    std::unique_ptr<http::RateLimitEngine<ClientServerClock>> rate_limit_engine{nullptr};
    // Owning pointer to the long-poll notifier. SyncNotifier holds a mutex
    // and condition_variable so it can't be copied or moved by value; a
    // unique_ptr keeps the runtime movable. Default-constructed runtimes
    // leave it null; sync_json and the mutators below lazily install an
    // instance the first time something sync-relevant happens, so legacy
    // callers that never touch /sync are unaffected.
    std::unique_ptr<sync::SyncNotifier> sync_notifier{};
};

// Convenience accessor that lazily attaches a SyncNotifier to the runtime
// and republishes the persistent store's current sync stream id. Called by
// the mutators below and the sync handler.
[[nodiscard]] auto ensure_sync_notifier(ClientServerRuntime& runtime) -> sync::SyncNotifier&;

// Test-only helper: replace the rate-limit engine with one that allows
// exactly one request per route per 60s window. The test scenarios in
// tests/unit/test_client_server.cpp install this to drive the 429 path
// from a single request without depending on the operator-configurable
// per-route caps. In production the engine is built in
// `start_client_server()` from `config.client_rate_limits()`. Not in the
// public API: declared here so test files can find it via the runtime
// header, defined in src/homeserver/client_server.cpp.
auto install_test_rate_limit_engine(ClientServerRuntime& runtime) -> void;
auto install_test_per_user_rate_limit_engine(ClientServerRuntime& runtime) -> void;

// Sync surface mutators. Each enqueues the row through the persistent
// store and bumps the SyncNotifier so a parked /sync request can wake.
// Returns true on success, false if the store rejected the row.
[[nodiscard]] auto push_to_device_message(ClientServerRuntime& runtime, database::PersistentToDeviceMessage message)
    -> bool;
[[nodiscard]] auto record_device_list_change(ClientServerRuntime& runtime, database::PersistentDeviceListChange change)
    -> bool;
[[nodiscard]] auto set_presence(ClientServerRuntime& runtime, database::PersistentPresence state) -> bool;
[[nodiscard]] auto set_account_data(ClientServerRuntime& runtime, database::PersistentAccountData data) -> bool;

struct ClientServerStartResult final
{
    bool started{false};
    std::string reason{};
    ClientServerRuntime runtime{};
};

[[nodiscard]] auto start_client_server(config::Config const& config) -> ClientServerStartResult;
[[nodiscard]] auto matrix_error(std::string_view errcode, std::string_view message) -> std::string;
[[nodiscard]] auto is_matrix_error_response(LocalHttpResponse const& response) noexcept -> bool;
[[nodiscard]] auto handle_client_server_request(ClientServerRuntime& runtime, LocalHttpRequest const& request,
                                                bool can_wait = true) -> DispatchResult;
[[nodiscard]] auto handle_client_server_http_request(ClientServerRuntime& runtime, std::string_view raw_request)
    -> LocalHttpResponse;
[[nodiscard]] auto device_count(ClientServerRuntime const& runtime, std::string_view user_id) noexcept -> std::size_t;
[[nodiscard]] auto joined_room_count(ClientServerRuntime const& runtime, std::string_view user_id) noexcept
    -> std::size_t;
[[nodiscard]] auto key_api_record_count(ClientServerRuntime const& runtime, std::string_view user_id) noexcept
    -> std::size_t;
[[nodiscard]] auto run_client_server_flow(config::Config const& config) -> OperationResult;

} // namespace merovingian::homeserver
