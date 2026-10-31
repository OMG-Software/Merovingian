// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/federation/inbound_ingestion.hpp"
#include "merovingian/homeserver/client_outbound_proxy.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/http/request.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
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
    // Per-IP limits never key on it directly: see rate_limit_client_key.
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
    // Application Service API, "Timestamp massaging": the `ts` an application service appended to
    // PUT /rooms/{roomId}/send/... or PUT /rooms/{roomId}/state/..., already validated, to become the
    // event's origin_server_ts. Set only by the client-server dispatcher after it has matched an
    // as_token; it is never read from the wire, so no other caller can set it.
    std::optional<std::int64_t> origin_server_ts{};
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
    // The Matrix errcode for a failure, carried from OperationResult::errcode so
    // the client API can return it rather than one guessed from the status.
    // Internal only: never written to the wire by format_response.
    std::string errcode{};
    // A media download's stored upload filename (ADR-0211), for the client API
    // to put in Content-Disposition. Internal only, like errcode: a field, not a
    // header, so no caller that writes `headers` to the wire can leak it.
    std::string media_filename{};
};

// Resolves the client address to attribute a request to, honouring
// `server.trusted_proxies`: when the direct TCP peer is a configured trusted
// proxy, X-Forwarded-For (every header line, in order, as one list) is walked
// from the right past trusted proxies and the first other entry is the client
// (0.12.13 audit item 4). The leftmost entries are whatever the client sent and
// never decide. A malformed entry at that position falls back to the direct
// peer. Returns "unknown" when no peer address is available (test paths that
// skip the transport layer), never an empty string, so callers cannot
// accidentally treat "no address" as "no limit".
[[nodiscard]] auto effective_client_ip(LocalHttpRequest const& request, std::vector<std::string> const& trusted_proxies)
    -> std::string;

// The key a per-IP limit counts a request under: effective_client_ip reduced
// by http::client_address_key, so IPv6 clients are grouped by
// server.http.ipv6_client_prefix_length. Shared by the client-server rate
// limiter and the federation key-resolution budget: behind the reverse-proxy
// deployment the shipped example config describes, every caller's direct
// peer is 127.0.0.1.
[[nodiscard]] auto rate_limit_client_key(LocalHttpRequest const& request, config::ServerConfig const& server)
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

// True when this server already stores `event_id` in `room_id`, in any status (ADR-0285). Takes
// runtime.mutex itself. Used before a re-sent PDU is verified: the main-process /send handler
// (runtime.federation.pdu_already_stored) and main's side of a worker's pdu_ingest relay.
[[nodiscard]] auto pdu_event_already_stored(HomeserverRuntime& runtime, std::string_view room_id,
                                            std::string_view event_id) -> bool;

// Fetches `event_id` of `room_id` from `origin` with GET /_matrix/federation/v1/event/{eventId}
// and stores it through the verified backfill path (signature, hash and auth checked; stored as
// an outlier, with the state at it when `origin`'s /state_ids snapshot supplies that; never
// stored unverified). True when the event is stored afterwards, including when it already was.
// Every call draws from `deadline`. Call WITHOUT runtime.mutex held: it takes the lock itself
// where it reads or writes the store and releases it for every network call.
[[nodiscard]] auto fetch_remote_event_into_store(HomeserverRuntime& runtime, std::string_view room_id,
                                                 std::string_view origin, std::string_view event_id,
                                                 OutboundDeadline const& deadline) -> bool;

} // namespace merovingian::homeserver
