// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/http/keep_alive.hpp"

#include <cstdint>
#include <string>

namespace merovingian::http
{

struct SlowlorisPolicy final
{
    std::uint32_t min_bytes_per_second{64U};
    std::uint32_t grace_seconds{5U};
    std::uint32_t header_deadline_seconds{30U};
};

struct RequestProgress final
{
    std::uint64_t bytes_received{0U};
    std::uint32_t elapsed_seconds{0U};
};

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

[[nodiscard]] auto slowloris_policy_is_valid(SlowlorisPolicy const& policy) noexcept -> bool;
[[nodiscard]] auto request_progress_is_too_slow(RequestProgress progress, SlowlorisPolicy policy) noexcept -> bool;
[[nodiscard]] auto slowloris_policy_summary(SlowlorisPolicy const& policy) -> std::string;

// Phase-aware composition of the slowloris and keep-alive close policies.
// Returns true when the connection must be closed given its phase and
// per-request progress:
//   - awaiting_request: closed once the keep-alive idle window passes; the
//     slowloris rate is deliberately not applied (a quiet connection is not a
//     slow client).
//   - reading_request: closed when the slowloris policy judges the request
//     progress too slow.
// An invalid keep-alive policy closes immediately (fail closed).
[[nodiscard]] auto connection_should_close(ConnectionPhase phase, RequestProgress progress,
                                           SlowlorisPolicy const& slowloris, KeepAlivePolicy const& keep_alive) noexcept
    -> bool;

} // namespace merovingian::http