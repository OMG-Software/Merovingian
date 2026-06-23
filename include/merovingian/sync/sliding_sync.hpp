// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <chrono>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

// MSC4186 Simplified Sliding Sync — request/response types.
// Spec: https://github.com/matrix-org/matrix-spec-proposals/blob/main/proposals/4186-simplified-sliding-sync.md
//
// Served at: POST /_matrix/client/unstable/org.matrix.msc4186/sync
// Advertised via: GET /_matrix/client/versions → unstable_features["org.matrix.msc4186"] and
// unstable_features["org.matrix.simplified_msc3575"]

namespace merovingian::sync
{

// ──────────────────────────────────────────────────────────────────────────────
// Request types
// ──────────────────────────────────────────────────────────────────────────────

// MSC4186 §lists[*].ranges — a half-inclusive window [start, end].
struct SlidingSyncRange final
{
    std::uint64_t start{0U};
    std::uint64_t end{0U};
};

// MSC4186 §lists[*].filters — predicates for narrowing the room list.
struct SlidingSyncFilters final
{
    std::optional<bool> is_encrypted{};
    std::optional<bool> is_invite{};
    std::optional<bool> is_dm{};
    std::optional<bool> is_favourite{};
    std::vector<std::string> room_types{};     // m.room.create content.type allowlist
    std::vector<std::string> not_room_types{}; // m.room.create content.type denylist
};

// MSC4186 §lists[*] — one named room list with windowing and sort criteria.
struct SlidingSyncList final
{
    std::vector<SlidingSyncRange> ranges{};
    // Sort order: "by_recency", "by_notification_count", "by_name" (applied left-to-right).
    std::vector<std::string> sort{};
    // Each pair is [event_type, state_key]; "*" is a wildcard for either component.
    std::vector<std::pair<std::string, std::string>> required_state{};
    std::uint64_t timeline_limit{20U};
    std::optional<SlidingSyncFilters> filters{};
    bool include_heroes{false};
    // Only events whose type appears here advance a room's recency position.
    // Empty means all event types count.
    std::vector<std::string> bump_event_types{};
};

// MSC4186 §room_subscriptions[roomId] — subscribe to a specific room regardless of list membership.
struct SlidingSyncRoomSubscription final
{
    std::vector<std::pair<std::string, std::string>> required_state{};
    std::uint64_t timeline_limit{20U};
    bool include_heroes{false};
};

// ── Extension request structs ─────────────────────────────────────────────────

// MSC4186 §extensions.to_device
struct ExtToDeviceRequest final
{
    bool enabled{false};
    std::uint64_t limit{20U};
    // Opaque position from a prior to_device response (next_batch).
    std::optional<std::string> since{};
};

// MSC4186 §extensions.e2ee
struct ExtE2eeRequest final
{
    bool enabled{false};
};

// MSC4186 §extensions.account_data
struct ExtAccountDataRequest final
{
    bool enabled{false};
};

// MSC4186 §extensions.receipts
struct ExtReceiptsRequest final
{
    bool enabled{false};
    // Limit receipt delivery to these rooms; empty = all rooms in the response.
    std::vector<std::string> rooms{};
};

// MSC4186 §extensions.typing
struct ExtTypingRequest final
{
    bool enabled{false};
    // Limit typing delivery to these rooms; empty = all rooms in the response.
    std::vector<std::string> rooms{};
};

struct SlidingSyncExtensionRequests final
{
    std::optional<ExtToDeviceRequest> to_device{};
    std::optional<ExtE2eeRequest> e2ee{};
    std::optional<ExtAccountDataRequest> account_data{};
    std::optional<ExtReceiptsRequest> receipts{};
    std::optional<ExtTypingRequest> typing{};
};

// MSC4186 §Request body
struct SlidingSyncRequest final
{
    // Client-chosen identifier; isolates connection state between concurrent clients.
    std::optional<std::string> conn_id{};
    std::map<std::string, SlidingSyncList> lists{};
    std::map<std::string, SlidingSyncRoomSubscription> room_subscriptions{};
    std::optional<SlidingSyncExtensionRequests> extensions{};
};

// ──────────────────────────────────────────────────────────────────────────────
// Response types
// ──────────────────────────────────────────────────────────────────────────────

// MSC4186 §ops — one operation describing how the client's room list changed.
struct SlidingSyncOp final
{
    // "SYNC" | "INVALIDATE" | "INSERT" | "DELETE" | "UPDATE"
    std::string op{};
    // Present for SYNC and INVALIDATE.
    std::optional<SlidingSyncRange> range{};
    // Present for SYNC — the ordered room IDs covering the range.
    std::vector<std::string> room_ids{};
    // Present for INSERT, DELETE, UPDATE — the affected list position.
    std::optional<std::uint64_t> index{};
    // Present for INSERT and UPDATE — the room at that position.
    std::optional<std::string> room_id{};
};

// MSC4186 §lists[*] response
struct SlidingSyncListResponse final
{
    std::uint64_t count{0U}; // total rooms matching the list's filters
    std::vector<SlidingSyncOp> ops{};
};

// MSC4186 §rooms[roomId] hero — a notable room member shown in the room name.
struct SlidingSyncHero final
{
    std::string user_id{};
    std::optional<std::string> display_name{};
    std::optional<std::string> avatar_url{};
};

// MSC4186 §rooms[roomId] — per-room data included in the response.
struct SlidingSyncRoomResponse final
{
    std::optional<std::string> name{};
    std::optional<std::string> avatar{};
    // True the first time this room appears in a response for this connection.
    bool initial{false};
    bool is_dm{false};
    std::optional<std::uint64_t> joined_count{};
    std::optional<std::uint64_t> invited_count{};
    std::optional<std::uint64_t> notification_count{};
    std::optional<std::uint64_t> highlight_count{};
    // Number of events received during the current long-poll wait.
    std::uint64_t num_live{0U};
    // origin_server_ts of the most recent event; 0 if unknown.
    std::uint64_t timestamp{0U};
    std::vector<SlidingSyncHero> heroes{};
    // Pre-serialised state event JSON objects matching required_state.
    std::vector<std::string> required_state_json{};
    // Pre-serialised timeline event JSON objects (chronological order).
    std::vector<std::string> timeline_json{};
    std::optional<std::string> prev_batch{};
    bool limited{false};
    // Set for invited rooms in place of timeline/state.
    std::optional<std::string> invite_state_json{};
};

// ── Extension response structs ────────────────────────────────────────────────

struct ExtToDeviceResponse final
{
    std::vector<std::string> events_json{};
    // Opaque position for the next to_device request (since field).
    std::string next_batch{};
};

struct ExtE2eeResponse final
{
    std::vector<std::string> changed{}; // user IDs whose device lists changed
    std::vector<std::string> left{};    // user IDs who left shared rooms
    std::map<std::string, std::uint64_t> device_one_time_keys_count{};
    std::vector<std::string> device_unused_fallback_key_types{};
};

struct ExtAccountDataResponse final
{
    std::vector<std::string> global_json{};
    // Key: room_id, value: serialised account-data events for that room.
    std::map<std::string, std::vector<std::string>> rooms_json{};
};

struct ExtReceiptsResponse final
{
    // Key: room_id, value: serialised m.receipt event content JSON.
    std::map<std::string, std::string> rooms_json{};
};

struct ExtTypingResponse final
{
    // Key: room_id, value: serialised m.typing event content JSON.
    std::map<std::string, std::string> rooms_json{};
};

struct SlidingSyncExtensionResponses final
{
    std::optional<ExtToDeviceResponse> to_device{};
    std::optional<ExtE2eeResponse> e2ee{};
    std::optional<ExtAccountDataResponse> account_data{};
    std::optional<ExtReceiptsResponse> receipts{};
    std::optional<ExtTypingResponse> typing{};
};

// MSC4186 §Response body
struct SlidingSyncResponse final
{
    // Opaque position token; returned as ?pos= on the next request.
    std::string pos{};
    std::map<std::string, SlidingSyncListResponse> lists{};
    std::map<std::string, SlidingSyncRoomResponse> rooms{};
    std::optional<SlidingSyncExtensionResponses> extensions{};
};

// ──────────────────────────────────────────────────────────────────────────────
// Connection state (stored in HomeserverRuntime)
// ──────────────────────────────────────────────────────────────────────────────

// Per-connection state required to compute incremental ops and the initial flag.
// Key in HomeserverRuntime::sliding_sync_connections:
//   user_id + "/" + device_id + "/" + (conn_id ?? "__default__")
struct SlidingSyncConnectionState final
{
    // Previous window contents per list — used to generate incremental ops.
    // Key: list name, value: ordered room IDs returned in the last response.
    std::map<std::string, std::vector<std::string>> list_prev_windows{};
    // Rooms that have appeared in at least one response for this connection,
    // mapped to the event ordering at which they were last returned.  This lets
    // the server compute per-room deltas and avoid re-sending unchanged rooms
    // when the global pos lags behind a room's last inclusion.
    std::unordered_map<std::string, std::uint64_t> rooms_seen{};
    // Stream position at the end of the last response (used for delta queries).
    std::uint64_t last_event_ordering{0U};
    std::uint64_t last_sync_stream_id{0U};
    // Wall clock of the last request; connections idle > 1 h are evicted.
    std::chrono::steady_clock::time_point last_used{};
};

} // namespace merovingian::sync
