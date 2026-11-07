// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::http
{

// Operator-tunable persistent-connection policy for the client and federation
// listeners (Matrix v1.19 is served over HTTP/1.1, where persistent
// connections are the default — RFC 9112 §9.3).
//
//   enabled           — master switch; false closes every connection after
//                        its response (the pre-0.12.1 behaviour).
//   idle_timeout_seconds — how long a kept-alive connection with no next
//                        request may be held open before the server closes
//                        it. Bounds how long a parked connection occupies a
//                        worker thread. Valid range 1..300.
//   max_connections   — cap on concurrently parked (idle, waiting for a next
//                        request) connections, process-wide. A kept-alive
//                        connection parks on a main-pool worker thread, so
//                        without a cap a client could park one worker per
//                        connection and stall every new request until each
//                        idle window expired. Valid range 1..4096.
struct KeepAlivePolicy final
{
    bool enabled{true};
    std::uint32_t idle_timeout_seconds{15U};
    std::uint32_t max_connections{8U};
};

} // namespace merovingian::http
