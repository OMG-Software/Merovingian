// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>

namespace merovingian::homeserver
{

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

} // namespace merovingian::homeserver
