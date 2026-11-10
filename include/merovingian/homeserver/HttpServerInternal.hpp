// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/ConnectionContext.hpp"
#include "merovingian/homeserver/HttpConnection.hpp"
#include "merovingian/homeserver/RoundOutcome.hpp"
#include "merovingian/net/ThreadPool.hpp"
#include "merovingian/sync/ParkedPoll.hpp"
#include "merovingian/sync/WakeReason.hpp"

#include <memory>

// Module-internal (ADR-0513): the parts of the HTTP transport in HttpServer.cpp
// that HttpConnectionDispatcher.cpp calls. Not public API.
namespace merovingian::homeserver::detail
{

// Per-read I/O timeout. Every wait in the transport is also bounded by the
// deadline of whichever phase the connection is in; this is the ceiling.
inline constexpr auto receive_timeout_milliseconds = 15000;

// The parked-poll registry's resume callback: hands the poll to `pool`. A pool
// that is stopping or full drops it, which closes the connection.
auto resume_parked_poll(net::ThreadPool& pool, std::unique_ptr<sync::ParkedPoll> base, sync::WakeReason reason)
    -> void;

// Serves one request round on `connection`. Returns close_connection or
// continue_keep_alive, or transferred when a long-poll was handed to the sync
// pool, which then owns the connection (`owner` is empty on return).
[[nodiscard]] auto serve_request_round(ConnectionContext& ctx, HttpConnection& connection, ConnectionOwner& owner)
    -> RoundOutcome;

} // namespace merovingian::homeserver::detail
