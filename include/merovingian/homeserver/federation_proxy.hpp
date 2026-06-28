// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/http/outbound_client.hpp"

#include <memory>
#include <string>
#include <string_view>

namespace merovingian::homeserver
{

struct HomeserverRuntime;
class WorkerPool;

// Intercepts inbound federation HTTP requests and forwards them to the
// out-of-process federation worker pool via encrypted IPC channels.
//
// The key-server endpoint (GET /_matrix/key/v2/server) is always handled
// locally — it serves this server's own signing key and must never be
// delegated to the worker.
//
// Requests with a room ID are routed to the worker shard that owns that
// room; non-room requests route to shard 0. If the selected shard is
// unhealthy, 503 is returned immediately (fail-closed; no in-process fallback).
class FederationProxy final
{
public:
    FederationProxy(config::FederationWorkerConfig const& cfg, HomeserverRuntime& runtime, std::string worker_path,
                    std::string config_path);
    ~FederationProxy();

    FederationProxy(FederationProxy const&) = delete;
    auto operator=(FederationProxy const&) -> FederationProxy& = delete;
    FederationProxy(FederationProxy&&) = delete;
    auto operator=(FederationProxy&&) -> FederationProxy& = delete;

    // Called in place of handle_federation_http_request() when the worker is active.
    [[nodiscard]] auto handle(LocalHttpRequest const& request) -> LocalHttpResponse;

    // Sends a pre-signed OutboundRequest to the worker shard for room_id to
    // execute. The HTTP call runs in the worker's thread pool; the signing key
    // never crosses the IPC boundary.
    [[nodiscard]] auto send_outbound_request(http::OutboundRequest const& request, std::string_view room_id)
        -> http::OutboundResult;

private:
    HomeserverRuntime& runtime_;
    std::unique_ptr<WorkerPool> pool_{};
};

} // namespace merovingian::homeserver
