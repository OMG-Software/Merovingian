// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/federation/inbound_ingestion.hpp"
// PHASE-B: forwarding includes, removed when consumers include the new headers directly.
#include "merovingian/homeserver/LocalHttpRequest.hpp"
#include "merovingian/homeserver/LocalHttpResponse.hpp"
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
