// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <merovingian/homeserver/vertical_slice.hpp>
#include <merovingian/net/shutdown_signal.hpp>
#include <merovingian/net/tcp_acceptor.hpp>

#include <cstdint>
#include <mutex>
#include <string>

namespace merovingian::homeserver
{

struct HttpServeStats final
{
    std::uint64_t accepted_connections{0U};
    std::uint64_t completed_requests{0U};
    std::uint64_t rejected_requests{0U};
};

// Read one HTTP/1.1 request from the connected socket, dispatch it through
// the existing local HTTP router, and write a single response. Closes the
// connection after the response is sent.
//
// `runtime_lock` serialises mutation of the shared runtime across listeners.
// The acceptor's fd is taken by value (already-accepted client socket).
auto serve_one_http_connection(int client_fd, HomeserverRuntime& runtime,
                               std::mutex& runtime_lock, HttpServeStats& stats) -> void;

// Block until `shutdown` fires, accepting connections from `acceptor` and
// dispatching them via `serve_one_http_connection`. Returns when either the
// shutdown signal fires or the acceptor becomes invalid.
auto serve_http(net::TcpAcceptor& acceptor, HomeserverRuntime& runtime,
                std::mutex& runtime_lock, net::ShutdownSignal& shutdown,
                HttpServeStats& stats) -> void;

} // namespace merovingian::homeserver
