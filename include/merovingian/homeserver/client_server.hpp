// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/dispatch_result.hpp"
#include "merovingian/homeserver/vertical_slice.hpp"
#include "merovingian/sync/sync_notifier.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
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

struct ClientRateLimitCounter final
{
    std::string bucket{};
    std::uint32_t count{0U};
    // Logical request-count clock value when the current window started.
    // The bucket-level cap comes from `http::endpoint_default_rate_limit`
    // for the request's method and target (with `ClientApiLimits::max_requests_per_bucket`
    // acting as an override ceiling for tests that need a tighter limit).
    std::uint64_t window_start_request{0U};
};

struct ClientKeyApiRecord final
{
    std::string user_id{};
    std::string device_id{};
    std::string endpoint{};
    std::string payload_summary{};
    std::size_t statement_count{0U};
};

struct ClientApiLimits final
{
    // 64 KiB covers real Matrix API calls including keys/upload (device keys +
    // many one-time keys) while staying well below the HTTP-layer 1 MiB cap in
    // http::RequestLimits::max_body_bytes.
    std::size_t max_body_bytes{65536U};
    std::uint32_t max_requests_per_bucket{64U};
    std::uint64_t rate_limit_window_requests{64U};
    std::size_t max_sync_rooms{16U};
    std::size_t max_sync_events_per_room{8U};
};

struct ClientServerRuntime final
{
    HomeserverRuntime homeserver{};
    ClientApiLimits limits{};
    std::vector<ClientDevice> devices{};
    std::vector<ClientKeyApiRecord> key_api_records{};
    std::vector<ClientRateLimitCounter> rate_limits{};
    std::uint64_t request_clock{0U};
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

// Sync surface mutators. Each enqueues the row through the persistent
// store and bumps the SyncNotifier so a parked /sync request can wake.
// Returns true on success, false if the store rejected the row.
[[nodiscard]] auto push_to_device_message(ClientServerRuntime& runtime,
                                          database::PersistentToDeviceMessage message) -> bool;
[[nodiscard]] auto record_device_list_change(ClientServerRuntime& runtime,
                                             database::PersistentDeviceListChange change) -> bool;
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
                                                bool can_wait = true)
    -> DispatchResult;
[[nodiscard]] auto handle_client_server_http_request(ClientServerRuntime& runtime, std::string_view raw_request)
    -> LocalHttpResponse;
[[nodiscard]] auto device_count(ClientServerRuntime const& runtime, std::string_view user_id) noexcept -> std::size_t;
[[nodiscard]] auto joined_room_count(ClientServerRuntime const& runtime, std::string_view user_id) noexcept
    -> std::size_t;
[[nodiscard]] auto key_api_record_count(ClientServerRuntime const& runtime, std::string_view user_id) noexcept
    -> std::size_t;
[[nodiscard]] auto run_client_server_flow(config::Config const& config) -> OperationResult;

} // namespace merovingian::homeserver
