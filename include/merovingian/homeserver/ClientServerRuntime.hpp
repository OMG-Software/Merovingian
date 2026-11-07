// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/PersistentAccountData.hpp"
#include "merovingian/database/PersistentDeviceListChange.hpp"
#include "merovingian/database/PersistentPresence.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/PersistentToDeviceMessage.hpp"
#include "merovingian/homeserver/ClientApiLimits.hpp"
#include "merovingian/homeserver/ClientDevice.hpp"
#include "merovingian/homeserver/ClientServerClock.hpp"
#include "merovingian/homeserver/ClientServerDispatchOptions.hpp"
#include "merovingian/homeserver/ClientServerStartOptions.hpp"
#include "merovingian/homeserver/DispatchResult.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/LocalHttpRequest.hpp"
#include "merovingian/homeserver/LocalHttpResponse.hpp"
#include "merovingian/homeserver/OperationResult.hpp"
#include "merovingian/homeserver/RegistrationValidationSession.hpp"
#include "merovingian/homeserver/UiaSession.hpp"
#include "merovingian/http/ConnectionLimiter.hpp"
#include "merovingian/http/InFlightBudget.hpp"
#include "merovingian/http/RateLimitEngine.hpp"
#include "merovingian/sync/LazyMemberTracker.hpp"
#include "merovingian/sync/SyncNotifier.hpp"

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

// Defined in ClientServerStartResult.hpp, which holds a ClientServerRuntime by value and so includes this header.
struct ClientServerStartResult;

// Security audit run-2 F-12 (ADR-0339). The spec bounds a tag's name (255 bytes) and nothing else about
// room tags; the server bounds the rest. A user's tags on one room hold at most `max_tags_per_room`
// entries, each tag's JSON value at most `max_tag_value_bytes`; the whole m.tag row is bounded by
// database::max_account_data_row_bytes as well. Over either, PUT .../tags/{tag} answers 400 M_TOO_LARGE.
inline constexpr std::size_t max_tag_name_bytes{255U};
inline constexpr std::size_t max_tags_per_room{100U};
inline constexpr std::size_t max_tag_value_bytes{1024U};

struct ClientServerRuntime final
{
    HomeserverRuntime homeserver{};
    ClientApiLimits limits{};
    std::vector<ClientDevice> devices{};
    std::vector<RegistrationValidationSession> registration_validation_sessions{};
    // Outstanding UIAA challenges. Bounded and TTL-pruned in
    // issue_uia_session(); in-memory only, because a UIAA session carries no
    // authority of its own (the credential travels in the auth block) and must
    // not survive a restart.
    std::vector<UiaSession> uia_sessions{};
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
    // Per-client cap on open connections, applied at accept time by the
    // client and federation listeners (ADR-0072). Heap-held so the runtime
    // stays movable and admitted connections' slots keep a stable address;
    // it outlives every pool task, like the runtime itself.
    std::unique_ptr<http::ConnectionLimiter> connection_limiter{std::make_unique<http::ConnectionLimiter>()};
    // Owning pointer to the long-poll notifier. SyncNotifier holds a mutex
    // and condition_variable so it can't be copied or moved by value; a
    // unique_ptr keeps the runtime movable. Default-constructed runtimes
    // leave it null; sync_json and the mutators below lazily install an
    // instance the first time something sync-relevant happens, so legacy
    // callers that never touch /sync are unaffected.
    std::unique_ptr<sync::SyncNotifier> sync_notifier{};
    // Which lazy-loaded membership events each /sync stream has been sent (ADR-0450). Heap-held because it owns a
    // mutex. Its mutex is a leaf below `homeserver.mutex`: /sync calls into it while holding the runtime mutex and
    // it never takes anything itself. In memory only; a restart sends every client its members again.
    std::unique_ptr<sync::LazyMemberTracker> lazy_member_tracker{std::make_unique<sync::LazyMemberTracker>()};
    // HTTP-4: shared admission for v3 and sliding-sync waits. Slots outlive the
    // initial dispatch and are released on completion, disconnect or failed handoff.
    std::unique_ptr<http::InFlightBudget> sync_user_budget{std::make_unique<http::InFlightBudget>()};
    std::unique_ptr<http::InFlightBudget> sync_device_budget{std::make_unique<http::InFlightBudget>()};
    // ADR-0121: admission for remote media fetches handed to the media fetch
    // pool, running or queued, keyed by the rate-limit client key. A slot is
    // taken before the handoff and released when the pool's task ends.
    std::unique_ptr<http::InFlightBudget> media_fetch_budget{std::make_unique<http::InFlightBudget>()};
    // Enabled only by the server's --debug startup argument. When enabled,
    // Sliding Sync emits request-shape diagnostics without request bodies,
    // connection IDs, tokens, or event content.
    bool sliding_sync_debug_diagnostics_enabled{false};
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
// header, defined in src/homeserver/ClientServerRuntime.cpp.
auto install_test_rate_limit_engine(ClientServerRuntime& runtime) -> void;
auto install_test_per_user_rate_limit_engine(ClientServerRuntime& runtime) -> void;

// Sync surface mutators. Each enqueues the row through the persistent
// store and bumps the SyncNotifier so a parked /sync request can wake.
// Returns true on success, false if the store rejected the row.
[[nodiscard]] auto push_to_device_message(ClientServerRuntime& runtime, database::PersistentToDeviceMessage message)
    -> bool;
[[nodiscard]] auto record_device_list_changes(ClientServerRuntime& runtime,
                                              std::vector<database::PersistentDeviceListChange> changes) -> bool;
[[nodiscard]] auto record_device_list_change(ClientServerRuntime& runtime, database::PersistentDeviceListChange change)
    -> bool;
[[nodiscard]] auto set_presence(ClientServerRuntime& runtime, database::PersistentPresence const& state) -> bool;
// One pass of the "presence-idle" job (CS API "Presence", "Idle timeout"; ADR-0492): every local user whose
// presence is `online` and whose last active time is over `presence_idle_timeout_ms` is set to `unavailable`,
// told to the servers that share a room with them, and long-polling syncs are woken. Takes runtime.mutex for
// the pass and makes no network call (the EDUs are queued). Returns how long the job sleeps before the next.
auto run_presence_idle_sweep(ClientServerRuntime& runtime) -> std::chrono::milliseconds;
[[nodiscard]] auto set_account_data(ClientServerRuntime& runtime, database::PersistentAccountData data) -> bool;
// set_account_data for a global row, refused past `max_global_types` distinct types (ADR-0173).
[[nodiscard]] auto set_global_account_data_within_cap(ClientServerRuntime& runtime,
                                                      database::PersistentAccountData data,
                                                      std::size_t max_global_types) -> database::CappedAccountDataStore;
// Expires typing whose timeout has passed at `now` (R13, ADR-0199): wakes sync waiters when a
// room's typing users changed, and sends m.typing typing:false to the remote servers in the room
// of each local user whose typing expired. Takes runtime.mutex itself. Returns how long to wait
// before the next call: until the earliest pending expiry, between 250 ms and 5 s. main.cpp runs
// it on the "typing-expiry" PeriodicJob; tests call it with a chosen clock.
[[nodiscard]] auto expire_typing_notifications(ClientServerRuntime& runtime, std::chrono::steady_clock::time_point now)
    -> std::chrono::milliseconds;
// set_account_data for a room row, refused past `max_room_types` distinct types the user holds in
// that room (R10, ADR-0197).
[[nodiscard]] auto set_room_account_data_within_cap(ClientServerRuntime& runtime, database::PersistentAccountData data,
                                                    std::size_t max_room_types) -> database::CappedAccountDataStore;

[[nodiscard]] auto start_client_server(config::Config const& config, ClientServerStartOptions options = {})
    -> ClientServerStartResult;
[[nodiscard]] auto matrix_error(std::string_view errcode, std::string_view message) -> std::string;
[[nodiscard]] auto matrix_error(std::string_view errcode, std::string_view message, std::uint32_t retry_after_ms)
    -> std::string;
[[nodiscard]] auto is_matrix_error_response(LocalHttpResponse const& response) noexcept -> bool;
[[nodiscard]] auto handle_client_server_request(ClientServerRuntime& runtime, LocalHttpRequest const& request,
                                                bool can_wait = true) -> DispatchResult;
// The same, with every option (ADR-0121). The transport uses this to run a
// main-pool request in RemoteMediaFetchMode::defer and to run a deferred one
// again on the media fetch pool.
[[nodiscard]] auto handle_client_server_request(ClientServerRuntime& runtime, LocalHttpRequest const& request,
                                                ClientServerDispatchOptions const& options) -> DispatchResult;
// HTTP-1 / HTTP-6 (ADR-0077): decides from the request head alone whether a
// media upload may have its body read under the raised
// security.media.max_upload_size cap. `head` is the request with an empty
// body. nullopt: its access token authenticates (a live session, or an
// application service's as_token). Otherwise the response to send before
// closing the connection unread: 401 M_MISSING_TOKEN or M_UNKNOWN_TOKEN (with
// soft_logout for an expired token), with CORS headers, as the dispatcher
// itself would answer. Takes the runtime lock; call it holding nothing.
[[nodiscard]] auto media_upload_authentication_refusal(ClientServerRuntime& runtime, LocalHttpRequest const& head)
    -> std::optional<LocalHttpResponse>;
[[nodiscard]] auto handle_client_server_http_request(ClientServerRuntime& runtime, std::string_view raw_request)
    -> LocalHttpResponse;
[[nodiscard]] auto device_count(ClientServerRuntime const& runtime, std::string_view user_id) noexcept -> std::size_t;
[[nodiscard]] auto joined_room_count(ClientServerRuntime const& runtime, std::string_view user_id) noexcept
    -> std::size_t;
[[nodiscard]] auto run_client_server_flow(config::Config const& config) -> OperationResult;

} // namespace merovingian::homeserver
