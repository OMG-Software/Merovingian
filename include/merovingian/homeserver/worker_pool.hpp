// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/worker_supervisor.hpp"
#include "merovingian/http/outbound_client.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::homeserver
{

struct HomeserverRuntime;

// Computes the federation worker shard index for a room ID.
// Non-room requests pass an empty room_id and are always routed to shard 0.
// Uses FNV-1a 32-bit: shard = fnv1a_32(room_id) % shards.
[[nodiscard]] auto federation_worker_shard_for(std::string_view room_id, std::uint32_t shards) noexcept -> std::size_t;

// Handles a "membership_ingest" IPC request (a worker relaying a send_join /
// send_leave / send_knock acceptance so it persists through main's own
// PersistentStore rather than the worker's — see docs/architecture.md,
// "Federation worker room staleness"). Exposed as a free function, separate
// from WorkerPool's private per-worker request-handler lambda, so it has a
// seam tests can drive directly without spawning a real worker subprocess
// (which would additionally have to clear the unrelated "remote is unknown"
// federation-policy gate before ever reaching this code). Takes and returns
// the same wire JSON a worker sends/receives over the IPC channel.
[[nodiscard]] auto handle_membership_ingest_request(HomeserverRuntime& runtime, std::string_view request_json)
    -> std::string;

// Handles an "edu_ingest" IPC request (a worker relaying an inbound EDU —
// m.typing, m.receipt, m.presence, m.direct_to_device, or
// m.device_list_update — so it reaches main's edu_sink instead of being
// dropped inside the worker process). See docs/architecture.md, "Federation
// worker EDU relay". Exposed as a free function for the same reason
// handle_membership_ingest_request is: a seam tests can drive directly
// without spawning a real worker subprocess. Takes and returns the same wire
// JSON a worker sends/receives over the IPC channel.
[[nodiscard]] auto handle_edu_ingest_request(HomeserverRuntime& runtime, std::string_view request_json) -> std::string;

// Handles an "invite_ingest" IPC request (a worker relaying an inbound
// PUT /_matrix/federation/{v1,v2}/invite acceptance so the invite's
// membership row, invite metadata, and event persist through main's own
// PersistentStore rather than the worker's — the same class of gap
// membership_ingest closes for send_join/send_leave/send_knock. See
// docs/architecture.md, "Federation worker invite relay"). Exposed as a free
// function for the same test-seam reason handle_membership_ingest_request
// is. Takes and returns the same wire JSON a worker sends/receives over the
// IPC channel.
[[nodiscard]] auto handle_invite_ingest_request(HomeserverRuntime& runtime, std::string_view request_json)
    -> std::string;

// Handles an "otk_claim_ingest" IPC request (a worker relaying an inbound
// POST /_matrix/federation/v1/user/keys/claim so the claim — which deletes
// the claimed one-time key — is decided against main's own PersistentStore
// instead of a worker's, avoiding the same key being handed out twice from
// two independent per-process snapshots (breaking Olm's single-use
// guarantee) and a worker's claim view going stale once its startup-time
// snapshot is exhausted even as fresh keys are uploaded through main. See
// docs/architecture.md, "Federation worker one-time-key claim relay").
// Exposed as a free function for the same test-seam reason
// handle_membership_ingest_request is. Takes and returns the same wire JSON
// a worker sends/receives over the IPC channel.
[[nodiscard]] auto handle_otk_claim_ingest_request(HomeserverRuntime& runtime, std::string_view request_json)
    -> std::string;

// Owns N out-of-process federation worker supervisors. Routes each inbound
// federation request to the worker that owns the request's room ID.
//
// Room-ID ownership:
//   shard = fnv1a_32(room_id) % N
// Non-room requests (key queries, profile queries, etc.) route to shard 0.
//
// IPC request handlers (pdu_ingest, sign_request) are wired against each
// worker's channel and operate on the supplied HomeserverRuntime.
class WorkerPool final
{
public:
    WorkerPool(config::FederationWorkerConfig const& cfg, HomeserverRuntime& runtime, std::string worker_path,
               std::string config_path);
    ~WorkerPool();

    WorkerPool(WorkerPool const&) = delete;
    auto operator=(WorkerPool const&) -> WorkerPool& = delete;
    WorkerPool(WorkerPool&&) = delete;
    auto operator=(WorkerPool&&) -> WorkerPool& = delete;

    // Forwards the request to the worker that owns room_id. Returns a 503
    // response if the selected worker is unhealthy and no reply is received.
    [[nodiscard]] auto handle(LocalHttpRequest const& request, std::string_view room_id) -> LocalHttpResponse;

    // Sends a pre-signed outbound HTTP request to the worker shard that owns
    // room_id for execution. The worker calls OutboundClient::perform() in its
    // own thread pool, keeping the main process handler thread free.
    // IPC timeout = request.total_timeout_seconds + 10 s buffer.
    [[nodiscard]] auto send_outbound_request(http::OutboundRequest const& request, std::string_view room_id)
        -> http::OutboundResult;

    // Tells the worker shard that owns room_id to re-read that room from the
    // database. The worker's PersistentStore is otherwise a snapshot taken
    // once at worker startup — it never learns about rooms created or joined
    // by the main process afterward (see docs/architecture.md, "Federation
    // worker room staleness"). Fire-and-forget: no reply is expected, and a
    // failure to deliver the notification (e.g. an unhealthy shard) is not
    // surfaced to the caller, matching the "best-effort cache refresh, not a
    // correctness-critical write" nature of this call.
    auto notify_room_changed(std::string_view room_id) -> void;

    // True when all configured workers are healthy.
    [[nodiscard]] auto healthy() const noexcept -> bool;

    // Stops all worker supervisors.
    auto stop() noexcept -> void;

    // Exposed for unit tests: which shard index would handle this room_id?
    [[nodiscard]] auto shard_for(std::string_view room_id) const noexcept -> std::size_t;

private:
    config::FederationWorkerConfig cfg_{};
    HomeserverRuntime& runtime_;
    std::string worker_path_;
    std::string config_path_;
    std::vector<std::unique_ptr<WorkerSupervisor>> workers_{};
};

} // namespace merovingian::homeserver
