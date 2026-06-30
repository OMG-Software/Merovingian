// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/federation_proxy.hpp"

#include "merovingian/federation/inbound_request.hpp"
#include "merovingian/homeserver/federation_request_routing.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/homeserver/worker_pool.hpp"
#include "merovingian/http/request.hpp"
#include "merovingian/observability/logger.hpp"

#include <chrono>
#include <cstdint>
#include <optional>
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

    // #323: verify the inbound X-Matrix signature in the main process before
    // forwarding to the worker. Only the verified peer identity crosses the
    // (authenticated) IPC channel; the raw peer Authorization header — which
    // carries the peer's reusable origin/key/sig credential — never reaches
    // the worker, so a compromised worker cannot harvest and replay it.
    wire_federation_callbacks(runtime_);
    auto signed_request_opt = std::optional<federation::SignedFederationRequest>{};
    auto const x_matrix = federation::parse_x_matrix_authorization_header(request.access_token);
    if (x_matrix.has_value())
    {
        auto signed_request = federation::SignedFederationRequest{};
        signed_request.method = request.method;
        signed_request.target = request.target;
        signed_request.origin = x_matrix->origin;
        // Bind the destination to this server's own name; the verifier rebuilds
        // the signed payload with our name, not the untrusted header claim, so a
        // request signed for a different server does not verify here.
        signed_request.destination = runtime_.config.server().server_name;
        signed_request.key_id = x_matrix->key_id;
        signed_request.signature = x_matrix->signature;
        signed_request.now_ts = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
                .count());
        signed_request.canonical_json_verified = true;
        signed_request.body = request.body;
        signed_request_opt = std::move(signed_request);
    }
    if (!signed_request_opt.has_value())
    {
        // 502 rather than 401: Synapse propagates 401 from federation responses
        // to the client, triggering an automatic logout. 502 signals a
        // server-side failure instead.
        return {502U, "malformed federation authorization"};
    }
    auto const verification = federation::verify_inbound_federation_signature(runtime_.federation, *signed_request_opt);
    if (!verification.accepted)
    {
        // Rejected in main (bad signature, unknown remote, policy denial): do
        // not forward to the worker. Return the verifier's error response.
        return {verification.error.status, verification.error.body};
    }

    // Forward only the verified identity to the worker. Clear access_token so
    // no raw credential accompanies the request; the IPC serializer (#323)
    // also strips any Authorization/X-Matrix header from `headers`.
    auto verified_request = request;
    verified_request.access_token.clear();
    verified_request.verified_origin = verification.identity.origin;
    verified_request.verified_key_id = verification.identity.key_id;
    verified_request.sig_verified = true;

    auto const room_id = federation_worker_room_id_from_request(request);
    return pool_->handle(verified_request, room_id);
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
