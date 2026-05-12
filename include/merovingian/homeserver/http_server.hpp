// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <mutex>
#include <string>

#include <merovingian/homeserver/client_server.hpp>
#include <merovingian/homeserver/tls.hpp>
#include <merovingian/net/shutdown_signal.hpp>
#include <merovingian/net/tcp_acceptor.hpp>

namespace merovingian::homeserver
{

struct HttpServeStats final
{
    std::uint64_t accepted_connections{0U};
    std::uint64_t completed_requests{0U};
    std::uint64_t rejected_requests{0U};
};

enum class HttpDispatchMode
{
    client_server,
    local_router,
};

// Read one HTTP/1.1 request from the connected socket, dispatch it through
// the selected runtime router, and write a single response. Closes the
// connection after the response is sent. Client listeners should use
// `client_server`; federation/internal compatibility paths can use
// `local_router` until those APIs have production adapters.
//
// `runtime_lock` serialises mutation of the shared runtime across listeners.
// The acceptor's fd is taken by value (already-accepted client socket).
auto serve_one_http_connection(int client_fd, ClientServerRuntime& runtime, std::mutex& runtime_lock,
                               HttpServeStats& stats, HttpDispatchMode dispatch_mode) -> void;

// Block until `shutdown` fires, accepting connections from `acceptor` and
// dispatching them via `serve_one_http_connection`. Returns when either the
// shutdown signal fires or the acceptor becomes invalid.
auto serve_http(net::TcpAcceptor& acceptor, ClientServerRuntime& runtime, std::mutex& runtime_lock,
                net::ShutdownSignal& shutdown, HttpServeStats& stats, HttpDispatchMode dispatch_mode) -> void;

// TLS variant of `serve_http`. The accepted socket is upgraded through the
// supplied OpenSSL-backed context before the shared HTTP parser/dispatcher sees
// any bytes.
auto serve_tls_http(TlsServerContext& tls_context, net::TcpAcceptor& acceptor, ClientServerRuntime& runtime,
                    std::mutex& runtime_lock, net::ShutdownSignal& shutdown, HttpServeStats& stats,
                    HttpDispatchMode dispatch_mode) -> void;

} // namespace merovingian::homeserver
