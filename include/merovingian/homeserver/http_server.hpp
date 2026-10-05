// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/client_server.hpp"
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

struct HttpServeStats final
{
    std::atomic<std::uint64_t> accepted_connections{0U};
    std::atomic<std::uint64_t> completed_requests{0U};
    std::atomic<std::uint64_t> rejected_requests{0U};

    HttpServeStats() = default;
    HttpServeStats(HttpServeStats&& other) noexcept
        : accepted_connections{other.accepted_connections.load(std::memory_order_relaxed)}
        , completed_requests{other.completed_requests.load(std::memory_order_relaxed)}
        , rejected_requests{other.rejected_requests.load(std::memory_order_relaxed)}
    {
        other.accepted_connections.store(0U, std::memory_order_relaxed);
        other.completed_requests.store(0U, std::memory_order_relaxed);
        other.rejected_requests.store(0U, std::memory_order_relaxed);
    }
    auto operator=(HttpServeStats&& other) noexcept -> HttpServeStats&
    {
        if (this != &other)
        {
            accepted_connections.store(other.accepted_connections.load(std::memory_order_relaxed),
                                       std::memory_order_relaxed);
            completed_requests.store(other.completed_requests.load(std::memory_order_relaxed),
                                     std::memory_order_relaxed);
            rejected_requests.store(other.rejected_requests.load(std::memory_order_relaxed), std::memory_order_relaxed);
            other.accepted_connections.store(0U, std::memory_order_relaxed);
            other.completed_requests.store(0U, std::memory_order_relaxed);
            other.rejected_requests.store(0U, std::memory_order_relaxed);
        }
        return *this;
    }
    HttpServeStats(HttpServeStats const&) = delete;
    auto operator=(HttpServeStats const&) = delete;
};

enum class HttpDispatchMode
{
    client_server,
    local_router,
    federation,
};

[[nodiscard]] auto dispatch_local_http_request(ClientServerRuntime& runtime, LocalHttpRequest const& request,
                                               HttpDispatchMode mode) -> LocalHttpResponse;

// Connection-level timing and limits the transport enforces (ADR-0077). The
// defaults are the production values; tests shorten them.
struct HttpServeTuning final
{
    // A new connection (and a TLS connection after its handshake) must send a
    // byte within this window, or the dispatcher closes it without a worker
    // ever touching it.
    std::chrono::milliseconds first_byte_timeout{5000};
    // Minimum request-body rate: once `body_rate_grace` has passed since the
    // body read started, the bytes received so far must be at least
    // `body_min_bytes_per_second` x (elapsed - grace); otherwise 408 and close.
    std::chrono::milliseconds body_rate_grace{10000};
    std::size_t body_min_bytes_per_second{16U * 1024U};
    // HTTP-8: after this many requests, or once the connection is this old,
    // the next response carries Connection: close.
    std::uint32_t max_requests_per_connection{1000U};
    std::chrono::seconds max_connection_lifetime{3600};
};

struct SyncAdmissionCaps final
{
    std::uint32_t global{0U};
    std::uint32_t per_user{0U};
    std::uint32_t per_device{0U};
};

// Resolve the configured long-poll admission budgets against the actual pool
// size. The global cap includes queued and active waits and cannot exceed the
// number of sync workers available to serve them.
[[nodiscard]] auto sync_admission_caps(config::HttpTransportConfig const& settings,
                                       std::size_t pool_worker_count) noexcept -> SyncAdmissionCaps;

// Construct the request limits from the startup config snapshot. Federation
// /send has its own configured body cap; all other request bodies use the
// server.http.max_body_size setting. Media uploads are expanded separately
// only after their request head passes the authentication gate.
[[nodiscard]] auto http_request_limits_for(ClientServerRuntime const& runtime, HttpDispatchMode dispatch_mode,
                                           std::string_view method, std::string_view target) -> http::RequestLimits;

// Owns every connection that is not being served (ADR-0077, audit finding
// HTTP-1): fresh connections before their first byte, and kept-alive connections
// between requests, all on one poll(2) thread (net::ConnectionParker). A
// connection reaches a worker of `pool` only once it is readable, at most
// pool-size connections are out at once, and at most max(1, pool-size / 4) of
// them may come from one client address (the TCP peer, IPv6 grouped as for the
// per-IP connection cap; a trusted proxy is exempt). One dispatcher serves
// every listener, so the caps are process-wide.
//
// Lifetime: construct, start() after process hardening (no thread may start
// before it, ADR-0082), hand to serve_http / serve_tls_http, and request_stop()
// once the listeners have returned and before the pools are stopped. Pool tasks
// keep the internals alive, so the object itself may be destroyed while a
// worker still holds a connection; that connection is closed, not re-parked.
// `runtime` and `stats` must outlive every pool task, as before.
class HttpConnectionDispatcher final
{
public:
    HttpConnectionDispatcher(ClientServerRuntime& runtime, HttpServeStats& stats, net::ThreadPool& pool,
                             net::ThreadPool* sync_pool = nullptr, HttpServeTuning tuning = {});
    HttpConnectionDispatcher(HttpConnectionDispatcher const&) = delete;
    auto operator=(HttpConnectionDispatcher const&) -> HttpConnectionDispatcher& = delete;
    HttpConnectionDispatcher(HttpConnectionDispatcher&&) = delete;
    auto operator=(HttpConnectionDispatcher&&) -> HttpConnectionDispatcher& = delete;
    ~HttpConnectionDispatcher();

    // Starts the dispatcher thread. False (fail closed) when it could not.
    [[nodiscard]] auto start() -> bool;
    // Closes every parked connection and stops the thread; bounded. Workers
    // that finish a request afterwards close their connection. Idempotent.
    auto request_stop() -> void;
    [[nodiscard]] auto running() const -> bool;

    class Impl;
    [[nodiscard]] auto impl() noexcept -> Impl&;

private:
    std::shared_ptr<Impl> m_impl; // SHARED_PTR: reviewed — pool tasks keep the dispatcher internals alive
};

// Read one HTTP/1.1 request from the connected socket, dispatch it through
// the selected runtime router, and write a single response. When sync_pool is
// provided and the request is a long-polling /sync that needs to wait, the fd
// is handed off to sync_pool (the main thread is freed immediately) and this
// function returns true. In all other cases it returns false and the caller
// closes the fd normally.
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
                                             std::string_view peer_addr = {}) -> bool;

// Block until `shutdown` fires, accepting connections from `acceptor` and
// parking them on `dispatcher`, which hands each to a worker once it is
// readable. Returns when the shutdown signal fires, the acceptor becomes
// invalid, or the dispatcher stops.
auto serve_http(net::TcpAcceptor& acceptor, HttpConnectionDispatcher& dispatcher, net::ShutdownSignal& shutdown,
                HttpDispatchMode dispatch_mode) -> void;

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
