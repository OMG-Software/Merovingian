// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::http
{

// What a connection is doing right now. With HTTP keep-alive a connection
// lives through more than one request, and the close policy differs by phase:
//   - awaiting_request: the previous request was fully served and the
//     connection is parked waiting for the next one. It is NOT a slow client
//     — the only bound is the keep-alive idle window.
//   - reading_request: bytes of a request are in flight. The slowloris
//     policy applies in full.
// Progress counters are per request (reset at each request boundary), so
// `reading_request` progress is never polluted by idle time between requests.
enum class ConnectionPhase : std::uint8_t
{
    awaiting_request,
    reading_request,
};

} // namespace merovingian::http
