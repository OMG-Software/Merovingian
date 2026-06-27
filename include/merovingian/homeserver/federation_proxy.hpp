// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/worker_supervisor.hpp"

#include <memory>
#include <string>

namespace merovingian::homeserver
{

struct HomeserverRuntime;

// Intercepts inbound federation HTTP requests and forwards them to the
// out-of-process federation worker via the encrypted IPC channel.
//
// The key-server endpoint (GET /_matrix/key/v2/server) is always handled
// locally — it serves this server's own signing key and must never be
// delegated to the worker.
//
// When the worker is unavailable and fallback_in_process is true, requests
// are handled by the main process. When fallback is false, 503 is returned.
class FederationProxy final
{
public:
    FederationProxy(config::FederationWorkerConfig const& cfg, HomeserverRuntime& runtime,
                    std::string worker_path, std::string config_path);
    ~FederationProxy();

    FederationProxy(FederationProxy const&)                    = delete;
    auto operator=(FederationProxy const&) -> FederationProxy& = delete;
    FederationProxy(FederationProxy&&)                         = delete;
    auto operator=(FederationProxy&&) -> FederationProxy&      = delete;

    // Called in place of handle_federation_http_request() when the worker is active.
    [[nodiscard]] auto handle(LocalHttpRequest const& request) -> LocalHttpResponse;

    [[nodiscard]] auto healthy() const noexcept -> bool;

private:
    config::FederationWorkerConfig cfg_;
    HomeserverRuntime& runtime_;
    std::unique_ptr<WorkerSupervisor> supervisor_;
};

} // namespace merovingian::homeserver
