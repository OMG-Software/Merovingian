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
    : cfg_{cfg}
    , runtime_{runtime}
{
    pool_ = std::make_unique<WorkerPool>(cfg_, runtime_, std::move(worker_path), std::move(config_path));
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

    if (pool_ && pool_->healthy())
    {
        auto const reply = pool_->handle(request, room_id);
        if (reply.status != 503U)
        {
            return reply;
        }
        LOG_WARNING("FederationProxy: worker shard unavailable for " + request.target);
    }

    if (cfg_.fallback_in_process)
    {
        return handle_federation_http_request(runtime_, request);
    }

    return {503U, R"({"errcode":"M_UNAVAILABLE","error":"Federation worker unavailable"})"};
}

auto FederationProxy::healthy() const noexcept -> bool
{
    return pool_ && pool_->healthy();
}

} // namespace merovingian::homeserver
