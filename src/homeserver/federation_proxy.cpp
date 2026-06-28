// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/federation_proxy.hpp"

#include "merovingian/homeserver/federation_request_routing.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/homeserver/worker_pool.hpp"
#include "merovingian/http/request.hpp"
#include "merovingian/observability/logger.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>

namespace merovingian::homeserver
{

FederationProxy::FederationProxy(config::FederationWorkerConfig const& cfg, HomeserverRuntime& runtime,
                                 std::string worker_path, std::string config_path)
    : runtime_{runtime}
{
    pool_ = std::make_unique<WorkerPool>(cfg, runtime_, std::move(worker_path), std::move(config_path));
}

FederationProxy::~FederationProxy()
{
    if (pool_)
    {
        pool_->stop();
    }
}

auto FederationProxy::handle(LocalHttpRequest const& request) -> LocalHttpResponse
{
    // GET /_matrix/key/v2/server is always served locally.
    if (request.target.find("/_matrix/key/v2/server") != std::string::npos)
    {
        return handle_federation_http_request(runtime_, request);
    }

    auto const room_id = federation_worker_room_id_from_request(request);
    return pool_->handle(request, room_id);
}

auto FederationProxy::send_outbound_request(http::OutboundRequest const& request, std::string_view room_id)
    -> http::OutboundResult
{
    if (!pool_)
    {
        return {false, {}, http::OutboundError::network_error, "federation worker pool not available"};
    }
    return pool_->send_outbound_request(request, room_id);
}

} // namespace merovingian::homeserver
