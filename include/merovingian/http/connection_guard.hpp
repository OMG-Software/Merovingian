// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/http/ConnectionPhase.hpp" // split-shim
#include "merovingian/http/RequestProgress.hpp" // split-shim
#include "merovingian/http/SlowlorisPolicy.hpp" // split-shim
#include "merovingian/http/keep_alive.hpp"

#include <cstdint>
#include <string>

namespace merovingian::http
{

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