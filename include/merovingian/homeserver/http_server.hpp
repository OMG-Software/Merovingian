// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/config/HttpTransportConfig.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/HttpConnectionDispatcher.hpp"
#include "merovingian/homeserver/HttpDispatchMode.hpp"
#include "merovingian/homeserver/HttpServeStats.hpp"
#include "merovingian/homeserver/HttpServeTuning.hpp"
#include "merovingian/homeserver/MediaFetchAdmissionCaps.hpp"
#include "merovingian/homeserver/SyncAdmissionCaps.hpp"
#include "merovingian/homeserver/dispatch_result.hpp"
#include "merovingian/homeserver/tls.hpp"
#include "merovingian/http/request_limits.hpp"
#include "merovingian/net/shutdown_signal.hpp"
#include "merovingian/net/tcp_acceptor.hpp"
#include "merovingian/net/thread_pool.hpp"

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

namespace merovingian::homeserver
{

[[nodiscard]] auto dispatch_local_http_request(ClientServerRuntime& runtime, LocalHttpRequest const& request,
                                               HttpDispatchMode mode) -> LocalHttpResponse;

// Resolve the configured long-poll admission budgets against the actual pool
// size. The global cap includes queued and active waits and cannot exceed the
// number of sync workers available to serve them.
[[nodiscard]] auto sync_admission_caps(config::HttpTransportConfig const& settings,
                                       std::size_t pool_worker_count) noexcept -> SyncAdmissionCaps;

// Resolve the configured media fetch admission (ADR-0121). One client is never
// promised more than the whole budget. The media fetch pool's queue is as deep
// as the global cap, so an admitted handoff is never refused for queue space.
[[nodiscard]] auto media_fetch_admission_caps(config::HttpTransportConfig const& settings) noexcept
    -> MediaFetchAdmissionCaps;

// Construct the request limits from the startup config snapshot. Federation
// /send has its own configured body cap; all other request bodies use the
// server.http.max_body_size setting. Media uploads are expanded separately
// only after their request head passes the authentication gate.
[[nodiscard]] auto http_request_limits_for(ClientServerRuntime const& runtime, HttpDispatchMode dispatch_mode,
                                           std::string_view method, std::string_view target) -> http::RequestLimits;

// Read one HTTP/1.1 request from the connected socket, dispatch it through
// the selected runtime router, and write a single response. When sync_pool is
// provided and the request is a long-polling /sync that needs to wait, the fd
// is handed off to sync_pool (the main thread is freed immediately) and this
// function returns true; likewise to media_fetch_pool for a remote media
// request that must fetch from the origin (ADR-0121). In all other cases it
// returns false and the caller closes the fd normally.
//
// The acceptor's fd is taken by value (already-accepted client socket).
// `peer_addr` is the dotted-decimal or colon-separated peer IP captured at
// accept() time; it is threaded onto LocalHttpRequest::remote_addr so the
// rate limiter can key per-IP buckets. Empty string is safe (falls back to
// the "unknown" synthetic key used by tests that skip transport).
//
// Direct callers keep the one-request-per-call contract: there is no
// dispatcher to park the connection on, so it is never kept alive.
[[nodiscard]] auto serve_one_http_connection(int client_fd, ClientServerRuntime& runtime, HttpServeStats& stats,
                                             HttpDispatchMode dispatch_mode, net::ThreadPool* sync_pool = nullptr,
                                             std::string_view peer_addr = {},
                                             net::ThreadPool* media_fetch_pool = nullptr) -> bool;

// Block until `shutdown` fires, accepting connections from `acceptor` and
// parking them on `dispatcher`, which hands each to a worker once it is
// readable. Returns when the shutdown signal fires, the acceptor becomes
// invalid, or the dispatcher stops.
auto serve_http(net::TcpAcceptor& acceptor, HttpConnectionDispatcher& dispatcher, net::ShutdownSignal& shutdown,
                HttpDispatchMode dispatch_mode) -> void;

// The answer to `GET /_merovingian/health` (ADR-0479): 200 with the fixed body `ok` while the server serves
// requests, 503 with the fixed body `unavailable` once it has stopped accepting them. Nothing else is ever in it.
[[nodiscard]] auto health_probe_response(bool serving) -> LocalHttpResponse;

// TLS variant. The handshake runs on a worker, once the ClientHello bytes are
// readable, bounded by the handshake timeout and counted against the client's
// share of workers like any request.
auto serve_tls_http(TlsServerContext& tls_context, net::TcpAcceptor& acceptor, HttpConnectionDispatcher& dispatcher,
                    net::ShutdownSignal& shutdown, HttpDispatchMode dispatch_mode) -> void;

// Single-listener conveniences (tests, embeds): each builds and starts its own
// dispatcher over `pool`, serves until `shutdown`, then stops it. Production
// uses one shared dispatcher for every listener (src/main.cpp).
auto serve_http(net::TcpAcceptor& acceptor, ClientServerRuntime& runtime, net::ShutdownSignal& shutdown,
                HttpServeStats& stats, HttpDispatchMode dispatch_mode, net::ThreadPool& pool,
                net::ThreadPool* sync_pool = nullptr, HttpServeTuning tuning = {}) -> void;

auto serve_tls_http(TlsServerContext& tls_context, net::TcpAcceptor& acceptor, ClientServerRuntime& runtime,
                    net::ShutdownSignal& shutdown, HttpServeStats& stats, HttpDispatchMode dispatch_mode,
                    net::ThreadPool& pool, net::ThreadPool* sync_pool = nullptr, HttpServeTuning tuning = {}) -> void;

} // namespace merovingian::homeserver
