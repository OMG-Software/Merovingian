// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/core/SocketHandle.hpp"
#include "merovingian/homeserver/HttpDispatchMode.hpp"
#include "merovingian/homeserver/ParkingReservation.hpp"
#include "merovingian/homeserver/TlsConnection.hpp"
#include "merovingian/homeserver/TlsServerContext.hpp"
#include "merovingian/http/ConnectionLimiter.hpp"
#include "merovingian/net/ConnectionParker.hpp"

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>

namespace merovingian::homeserver
{

// Ownership: every connection is an HttpConnection behind a std::unique_ptr,
// owned by exactly one of the parker, one pool task, or one sync-pool task at
// any moment (ADR-0077). Destroying it closes the socket and releases
// everything it holds (per-IP slot, parking reservation).
using ConnectionOwner = std::unique_ptr<net::ConnectionParker::Connection>;

// One client connection and everything that travels with it.
class HttpConnection final : public net::ConnectionParker::Connection
{
public:
    HttpConnection(core::SocketHandle client_socket, HttpDispatchMode dispatch_mode, std::string peer,
                   std::string key) noexcept;
    HttpConnection(HttpConnection const&) = delete;
    auto operator=(HttpConnection const&) -> HttpConnection& = delete;
    HttpConnection(HttpConnection&&) = delete;
    auto operator=(HttpConnection&&) -> HttpConnection& = delete;
    // TLS state first (it does not own the descriptor), then an orderly
    // shutdown; ~socket closes the descriptor last.
    ~HttpConnection() override;

    [[nodiscard]] auto fd() const noexcept -> int override
    {
        return socket.native_handle();
    }

    // Pipelined bytes already read past the previous request, or TLS input
    // OpenSSL holds: the next request is here even if the socket is quiet.
    [[nodiscard]] auto has_buffered_input() const noexcept -> bool override
    {
        return !leftover.empty() || (tls.has_value() && tls->has_pending_input());
    }

    // Logs why a parked connection was closed: no first byte in time, or idle
    // past the keep-alive timeout.
    auto on_park_expired() noexcept -> void override;

    // Declared first so it is destroyed last: everything below may still
    // refer to the descriptor while it is torn down.
    core::SocketHandle socket;
    // ADR-0072: the connection's per-IP slot; empty when exempt.
    std::optional<http::ConnectionLimiter::Slot> connection_slot{};
    std::optional<TlsConnection> tls{};
    // Set on a TLS listener until the handshake has run (on a worker).
    std::optional<std::reference_wrapper<TlsServerContext>> tls_handshake_owed{};
    HttpDispatchMode mode;
    std::string peer_addr;
    // The per-client worker-share key; empty for a trusted proxy.
    std::string client_key;
    // Bytes read past the previous request (a pipelined next request).
    std::string leftover{};
    std::uint32_t requests_served{0U};
    std::chrono::steady_clock::time_point opened_at;
    bool first_request{true};
    // Held while the connection is parked (see ParkingReservation).
    std::optional<ParkingReservation> parked_reservation{};
    // C01: the same parking, counted against its client key, so a few keys
    // cannot fill the process-wide budgets. Empty for a trusted proxy.
    std::optional<http::ConnectionLimiter::Slot> parked_key_slot{};
};

[[nodiscard]] inline auto http_connection(ConnectionOwner const& owner) -> HttpConnection&
{
    // Only HttpConnections are ever parked on an HTTP dispatcher.
    return dynamic_cast<HttpConnection&>(*owner);
}

} // namespace merovingian::homeserver
