// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/dispatch_result.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/http/connection_limiter.hpp"
#include "merovingian/http/rate_limit.hpp"
#include "merovingian/sync/sliding_sync.hpp"
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
    std::string purpose{"register"};
    std::string medium{};
    std::string address{};
    std::string client_secret{};
    std::string client_ip{};
    std::optional<std::string> user_id{};
    std::optional<std::string> country{};
    std::optional<std::string> next_link{};
    std::uint64_t send_attempt{0U};
    std::uint64_t created_at_ms{0U};
    std::uint64_t updated_at_ms{0U};
    std::uint64_t validated_at_ms{0U};
};

struct ClientApiLimits final
{
    // The body limit is snapshotted from server.client_api.max_body_size at startup.
    std::size_t max_body_bytes{1024U * 1024U};
    std::uint32_t max_sync_rooms{1000U};
    std::uint32_t max_sync_events_per_room{100U};
    // POST /search has no per-room scope (unlike /messages) and no secondary
    // full-text index (see docs/architecture.md's "Server-side search"
    // section): it walks the joined-room subset of PersistentStore::events
    // directly. This bounds the number of candidate events a single request
    // will JSON-parse and text-match before it must stop and hand back a
    // `next_batch` continuation, so one cheap authenticated request cannot
    // force an O(store size) scan.
    std::uint32_t max_search_events_scanned{10000U};
    // GET /messages hides events the user may not see (m.room.history_visibility), and
    // any number of consecutive events can be hidden. This bounds how many events one page
    // examines before it returns what it has, with an `end` token to continue from; the spec
    // allows it ("an empty chunk does not necessarily imply that no more events are available").
    std::uint32_t max_messages_events_examined{10000U};
    std::uint32_t max_messages_page_size{500U};
    std::uint32_t max_context_events{100U};
    std::uint32_t max_search_page_size{100U};
    std::uint32_t max_search_context_events{100U};
    std::uint32_t max_registration_validation_sessions{1024U};
    std::uint32_t max_registration_validation_sessions_per_remote{16U};
    std::uint32_t max_uia_sessions{2048U};
    std::uint32_t max_safety_report_rows{1000U};
    std::uint32_t max_notifications_page_size{1000U};
    std::uint32_t max_relations_page_size{500U};
    std::uint32_t max_public_rooms_page_size{1000U};
    std::uint32_t max_hierarchy_rooms{1000U};
    // CSAZ-10: per-user caps on stored end-to-end key material and filters.
    // An upload over a cap is refused with M_TOO_LARGE; nothing is evicted.
    std::uint32_t max_one_time_keys_per_device{1000U};
    std::uint32_t max_key_signatures_per_user{10000U};
    std::uint32_t max_filters_per_user{1000U};
    sync::SlidingSyncLimits sliding_sync{500U, 1024U, 1024U};
    std::uint32_t sliding_sync_connections_per_device{16U};
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

// One outstanding User-Interactive Authentication challenge (spec §User-
// Interactive Authentication API). Issued when the server answers 401 with a
// flow the client must complete, and consumed when the client comes back with
// a matching `auth.session`.
//
// L-01/L-02 (security audit 2026-09): the session id used to be a compile-time
// constant shared by every client and every attempt (`merovingian-ui-auth`,
// `delete_device`, `delete_devices`). The spec treats the session id as the
// server's handle on one in-flight attempt; a constant is not a handle, and it
// tells an attacker exactly what to echo.
struct UiaSession final
{
    std::string session_id{};
    // The endpoint the challenge was issued for: a session minted for a device
    // deletion must not satisfy a registration challenge.
    std::string purpose{};
    std::uint64_t created_at_ms{0U};
};

struct ClientServerRuntime final
{
    HomeserverRuntime homeserver{};
    ClientApiLimits limits{};
    std::vector<ClientDevice> devices{};
    std::vector<ClientKeyApiRecord> key_api_records{};
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

// Startup-only options supplied by the process entry point. They are not
// configuration-file settings and cannot change after the runtime starts.
struct ClientServerStartOptions final
{
    bool debug_startup_enabled{false};
};

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
[[nodiscard]] auto key_api_record_count(ClientServerRuntime const& runtime, std::string_view user_id) noexcept
    -> std::size_t;
[[nodiscard]] auto run_client_server_flow(config::Config const& config) -> OperationResult;

} // namespace merovingian::homeserver
