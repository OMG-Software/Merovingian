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
    // GET /_matrix/key/v2/server is always served locally. Match the path
    // exactly so unrelated targets that merely contain this substring still go
    // through the worker and federation authorization path.
    if (is_federation_key_server_endpoint(request.target))
    {
        return handle_federation_http_request(runtime_, request);
    }

    // GET /_matrix/federation/v1/openid/userinfo is likewise always served
    // locally: the spec marks it unauthenticated (no X-Matrix signature to
    // verify), it carries no room_id to shard by, and the openid_tokens
    // table it consults lives only in the main process's persistent store.
    if (is_federation_openid_userinfo_endpoint(request.target))
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
        // Budgets pre-authentication remote-key resolution (#487). This is the
        // production path: verification happens here in the main process, before
        // anything is forwarded to the worker, so this is where the budget bites.
        //
        // Resolved through trusted_proxies rather than taken raw: behind the
        // reverse-proxy deployment the shipped example config describes, every
        // remote server's direct TCP peer is 127.0.0.1, which would collapse all
        // of them into one bucket and let ten new-peer resolutions a minute
        // reject every unrelated legitimate peer.
        signed_request.remote_addr = effective_client_ip(request, runtime_.config.server().trusted_proxies);
        signed_request_opt = std::move(signed_request);
    }
    if (!signed_request_opt.has_value())
    {
        // Log enough to identify WHICH peer and shape of header failed, without
        // ever recording the header itself: it carries the peer's reusable
        // origin/key/signature credential. Without this the rejection is an
        // opaque 502 in the access log and a peer whose PDUs are being dropped
        // is indistinguishable from one that never called.
        auto constexpr scheme = std::string_view{"X-Matrix "};
        observability::log_diagnostic(
            "federation_proxy", "federation_proxy.authorization_unparsed",
            {
                {"target",       observability::sanitized_http_target(request.target),        false},
                {"header_bytes", std::to_string(request.access_token.size()),                 false},
                {"scheme_ok",    request.access_token.starts_with(scheme) ? "true" : "false", false}
        },
            observability::LogEventSeverity::warning);
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

    if (federation_request_should_bypass_worker(verified_request))
    {
        observability::log_diagnostic("federation_proxy", "federation_proxy.bypass_worker",
                                      {
                                          {"target", observability::sanitized_http_target(request.target), false},
                                          {"reason", "edu_only_send",                                      false}
        });
        return handle_federation_http_request(runtime_, verified_request);
    }

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

auto FederationProxy::notify_room_changed(std::string_view room_id) -> void
{
    if (pool_)
    {
        pool_->notify_room_changed(room_id);
    }
}

auto FederationProxy::healthy() const noexcept -> bool
{
    return pool_ != nullptr && pool_->healthy();
}

} // namespace merovingian::homeserver
