// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/federation/inbound_ingestion.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/http/request.hpp"

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace merovingian::homeserver
{

struct LocalHttpRequest final
{
    std::string method{};
    std::string target{};
    std::string access_token{};
    std::string body{};
    // Parsed request headers (e.g. "Origin", "Authorization"). Populated by
    // `build_local_request` from the wire request head. Tests construct a
    // request directly and set this field to drive CORS logic.
    std::vector<http::Header> headers{};
    // Source IP address of the direct TCP peer (e.g. "192.0.2.1" or
    // "::1"). Set by the HTTP acceptor from getpeername(). Empty in
    // tests that do not exercise transport-level peer resolution.
    // When the peer is a configured trusted proxy, `allow()` replaces
    // this value with the leftmost X-Forwarded-For address before
    // constructing the per-IP rate-limit bucket key.
    std::string remote_addr{};
    // #323: when sig_verified is true, the X-Matrix request signature was
    // already verified by the main process over the authenticated IPC channel
    // and verified_origin/verified_key_id carry the authenticated peer identity.
    // access_token is empty in that case and Authorization headers are stripped
    // from `headers` before the frame crosses IPC, so a compromised worker
    // cannot harvest the peer's reusable credential. The worker builds a
    // SignedFederationRequest directly from these fields and skips re-verification.
    bool sig_verified{false};
    std::string verified_origin{};
    std::string verified_key_id{};
};

struct LocalHttpResponse final
{
    std::uint16_t status{500U};
    std::string body{};
    // Per-response headers. CORS preflight responses fill this with
    // `Access-Control-Allow-*` and `Vary: Origin`; `format_response` writes
    // the contents to the wire in insertion order, with the standard
    // `Content-Length` / `Content-Type` / `Connection: close` lines emitted
    // automatically.
    std::vector<std::pair<std::string, std::string>> headers{};
};

// Resolves the client address to attribute a request to, honouring
// `server.trusted_proxies`: when the direct TCP peer is a configured trusted
// proxy, the leftmost valid IP literal in X-Forwarded-For is used instead, so a
// per-IP bucket isolates each downstream caller rather than collapsing everything
// arriving through the proxy into one. Returns "unknown" when no peer address is
// available (test paths that skip the transport layer), never an empty string, so
// callers cannot accidentally treat "no address" as "no limit".
//
// Shared by the client-server rate limiter and the federation key-resolution
// budget. Both need it for the same reason: behind the reverse-proxy deployment
// the shipped example config describes, every caller's direct peer is 127.0.0.1.
[[nodiscard]] auto effective_client_ip(LocalHttpRequest const& request, std::vector<std::string> const& trusted_proxies)
    -> std::string;

[[nodiscard]] auto handle_local_http_request(HomeserverRuntime& runtime, LocalHttpRequest const& request)
    -> LocalHttpResponse;
[[nodiscard]] auto handle_federation_http_request(HomeserverRuntime& runtime, LocalHttpRequest const& request)
    -> LocalHttpResponse;
auto wire_federation_callbacks(HomeserverRuntime& runtime) -> void;

// Production inbound PDU ingestion path. Reserves a global stream_ordering and
// sync_stream_id, serializes on the event's room stripe, and releases the
// global runtime mutex for the backend commit so independent rooms can persist in
// parallel. The global mutex is re-acquired only to apply the committed rows to
// the in-memory store and update membership.
[[nodiscard]] auto ingest_pdu_event(HomeserverRuntime& runtime, federation::InboundPduEnvelope const& envelope)
    -> federation::PduIngestionResult;

} // namespace merovingian::homeserver
