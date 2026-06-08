// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/dispatch_result.hpp"
#include "merovingian/homeserver/tls.hpp"
#include "merovingian/net/shutdown_signal.hpp"
#include "merovingian/net/tcp_acceptor.hpp"
#include "merovingian/net/thread_pool.hpp"

#include <atomic>
#include <cstdint>
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
[[nodiscard]] auto serve_one_http_connection(int client_fd, ClientServerRuntime& runtime, HttpServeStats& stats,
                                             HttpDispatchMode dispatch_mode, net::ThreadPool* sync_pool = nullptr,
                                             std::string_view peer_addr = {}) -> bool;

// Block until `shutdown` fires, accepting connections from `acceptor` and
// submitting them to `pool` for dispatch. Returns when either the shutdown
// signal fires or the acceptor becomes invalid.
//
// When sync_pool is supplied, long-polling /sync connections are offloaded to
// it, keeping the main pool free for regular requests. Passing nullptr falls
// back to the original behaviour (sync waits block the main pool thread).
auto serve_http(net::TcpAcceptor& acceptor, ClientServerRuntime& runtime, net::ShutdownSignal& shutdown,
                HttpServeStats& stats, HttpDispatchMode dispatch_mode, net::ThreadPool& pool,
                net::ThreadPool* sync_pool = nullptr) -> void;

// TLS variant of `serve_http`. The accepted socket is upgraded through the
// supplied OpenSSL-backed context in the worker thread. sync_pool is accepted
// for API symmetry; TLS async offload is not yet implemented (sync waits use
// the main pool thread).
auto serve_tls_http(TlsServerContext& tls_context, net::TcpAcceptor& acceptor, ClientServerRuntime& runtime,
                    net::ShutdownSignal& shutdown, HttpServeStats& stats, HttpDispatchMode dispatch_mode,
                    net::ThreadPool& pool, net::ThreadPool* sync_pool = nullptr) -> void;

} // namespace merovingian::homeserver
