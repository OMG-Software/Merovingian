// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::homeserver
{

// The shipped size of the main request pool (server.http.request_threads,
// HTTP-1 / ADR-0077). The running server sizes its pool, and the caps below,
// from the configured value; this default is what a runtime built without a
// configuration uses.
inline constexpr std::uint32_t default_main_request_pool_threads{16U};

// Client-triggered outbound proxying (ADR-0079).
//
// Some client requests make this server call another one before answering:
// publicRooms with ?server=, a remote room-alias lookup, a remote media
// download or thumbnail. Several of them are reachable without authentication
// (the spec permits it), and each holds a main-pool thread for the whole
// round trip, so an unbounded number of them lets one attacker-controlled peer
// that never answers stall every other request. Every such call therefore runs
// under this policy: a small in-flight budget, and a short total deadline.
struct ClientOutboundProxyPolicy final
{
    // Calls in flight across every client. Half of the main request pool, so
    // the other half always stays available to requests that never leave this
    // server.
    std::uint32_t global_cap{default_main_request_pool_threads / 2U};
    // Calls in flight for one client address (rate_limit_client_key, which
    // honours trusted_proxies and groups IPv6 by prefix).
    std::uint32_t per_client_cap{1U};
    // Total wall-clock budget for a directory lookup (publicRooms, alias):
    // server discovery plus the request.
    std::uint32_t directory_deadline_seconds{10U};
    // Total wall-clock budget for a remote media fetch: server discovery, the
    // federation media request, and the legacy fallback together.
    std::uint32_t media_deadline_seconds{30U};
    // Total wall-clock budget for the remote half of one /keys/query or /keys/claim, however many
    // servers it names: every discovery and every request draws from it (F-17, ADR-0350).
    std::uint32_t remote_keys_deadline_seconds{30U};
    // The most distinct remote servers one /keys/query or /keys/claim asks. Servers past it are
    // reported in `failures` without being contacted.
    std::uint32_t remote_keys_max_servers{16U};
    // Slack the federation-worker round trip may add on top of the deadline for
    // the worker to hand its (already timed-out) result back.
    std::uint32_t worker_margin_seconds{2U};
    // Advertised in the 429 answer.
    std::uint32_t retry_after_ms{1000U};
    // F-42 (ADR-0361): calls to the external trust-and-safety policy server in flight, across every surface
    // (registration, createRoom, media, inbound federation). Each holds a request thread for the whole round
    // trip, up to policy_server_timeout, and several surfaces are reached before authentication. A quarter of
    // the main pool, so the rest stays free for requests that never leave this server.
    std::uint32_t policy_server_global_cap{default_main_request_pool_threads / 4U};
    // The share of those one surface may hold, so a flood of one (verified federation requests) cannot leave
    // registration or room creation without a place.
    std::uint32_t policy_server_per_surface_cap{default_main_request_pool_threads / 8U};
};

} // namespace merovingian::homeserver
