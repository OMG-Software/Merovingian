// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::config
{

// Push Gateway API delivery configuration (Matrix v1.19 push-gateway-api /
// CS API push-notifications module). `enabled` gates the entire outbound
// delivery path and defaults to false, mirroring OidcConfig's pattern, so
// merging this capability cannot cause an existing deployment to start
// sending traffic to gateways on upgrade — an operator must explicitly opt
// in. Timeouts mirror IdentityServerConfig's operator-tunable connect/total
// pair; a pusher's gateway URL is client-supplied (any client can register
// one), so these bound how long the homeserver waits on a host it does not
// control.
struct PushConfig final
{
    bool enabled{false};
    std::uint32_t connect_timeout_seconds{10U};
    std::uint32_t total_timeout_seconds{30U};
    std::uint32_t max_pushers_per_delivery{25U};
    std::uint32_t max_in_flight_deliveries{256U};
    // OUT-3, ADR-0151: distinct pushers one user may register, and the circuit
    // breaker for a gateway host that keeps failing (consecutive transport
    // failures, timeouts or 5xx before it opens; seconds it then stays open).
    std::uint32_t max_pushers_per_user{20U};
    std::uint32_t gateway_failure_threshold{3U};
    std::uint32_t gateway_cooldown_seconds{300U};
};

} // namespace merovingian::config
