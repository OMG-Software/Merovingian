// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::config
{

// HTTP/1.1 persistent-connection (keep-alive) policy. Matrix v1.19 is served
// over HTTP/1.1, where persistent connections are the default; keeping a
// connection open saves a full TLS handshake per request. The fields mirror
// `merovingian::http::KeepAlivePolicy` (validated by
// `http::keep_alive_policy_is_valid()` and `config::validate()`):
//   keep_alive              — master switch; false restores the historical
//                             close-after-every-response behaviour.
//   keep_alive_idle_seconds — how long a kept-alive connection may sit idle
//                             (no next request) before the server closes it.
//                             Range 1..300; restart required.
//   keep_alive_max_connections — process-wide cap on connections parked idle
//                             waiting for a next request. A parked connection
//                             is held by the connection dispatcher, not by a
//                             worker thread (ADR-0077), so the cap bounds open
//                             descriptors and memory and need not relate to
//                             request_threads. Range 1..4096; restart required.
//   max_connections_per_ip  — open connections one client key may hold on
//                             the client and federation listeners, decided at
//                             accept time (ADR-0072). Addresses listed in
//                             server.trusted_proxies are exempt. Range
//                             1..65535; restart required.
//   ipv6_client_prefix_length — prefix length IPv6 clients are grouped by for
//                             per-client limits (the connection cap, the
//                             per-client worker share and the rate limiter).
//                             Range 1..128; restart required.
//   request_threads         — threads in the main request pool that serves
//                             every listener (ADR-0077). One client address
//                             may hold at most max(1, request_threads / 4) of
//                             them at once, and client-triggered outbound
//                             proxying at most request_threads / 2 in total
//                             (ADR-0079). Range 4..256; default 16; restart
//                             required.
struct HttpTransportConfig final
{
    bool keep_alive{true};
    std::uint32_t keep_alive_idle_seconds{15U};
    std::uint32_t keep_alive_max_connections{256U};
    std::uint32_t max_connections_per_ip{256U};
    std::uint8_t ipv6_client_prefix_length{64U};
    std::uint32_t request_threads{32U};
    std::uint32_t sync_threads{128U};
    std::uint32_t sync_max_in_flight{128U};
    std::uint32_t sync_max_per_user{4U};
    std::uint32_t sync_max_per_device{2U};
    // Remote media fetch pool (ADR-0121). A remote media download or
    // thumbnail that must fetch from the origin is handed to this pool, so no
    // main-pool thread waits on a remote server. media_fetch_threads: workers,
    // 1..256. media_fetch_max_in_flight: fetches running or queued, 1..1024.
    // media_fetch_max_per_client: of those, for one client (the rate-limit
    // key, trusted_proxies honoured), 1..256, never more than the in-flight
    // cap. Over either cap a request gets 429 at once. Restart required.
    std::uint32_t media_fetch_threads{16U};
    std::uint32_t media_fetch_max_in_flight{64U};
    std::uint32_t media_fetch_max_per_client{8U};
    std::uint32_t max_start_line_bytes{8192U};
    std::uint32_t max_header_bytes{32768U};
    std::uint32_t max_header_count{100U};
    std::string max_body_size{"1MiB"};
};

} // namespace merovingian::config
