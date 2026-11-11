// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>

namespace merovingian::push
{

// OUT-3, ADR-0151: when a push gateway host cannot be reached
// `failure_threshold` times in a row (see push::gateway_circuit_outcome: a
// connection, TLS, DNS or timeout failure; never an HTTP answer such as a 5xx,
// which concerns one notification), its circuit opens and the host
// is not contacted for `cooldown`. After that, one request per cooldown window
// is let through as a probe until one succeeds. Gateway URLs are client-supplied,
// so the number of hosts tracked is bounded by `max_hosts` (the least recently
// failing host is forgotten first).
struct GatewayCircuitBreakerPolicy final
{
    std::uint32_t failure_threshold{3U};
    std::chrono::seconds cooldown{300};
    std::size_t max_hosts{4096U};
    // ADR-0634: how long a host that answered promptly counts as reachable (see
    // GatewayCircuitBreaker::reachable_recently).
    std::chrono::seconds reachable_ttl{3600};
};

} // namespace merovingian::push
