// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/worker_supervisor.hpp"

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
