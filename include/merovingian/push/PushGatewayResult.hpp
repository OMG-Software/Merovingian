// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/http/OutboundError.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace merovingian::push
{

// Outcome of one PushGatewayClient::notify() call.
//   - `disabled == true` means config.enabled was false and no network call
//     was made at all (the config-gate fail-closed path).
//   - `ok == false` (with `disabled == false`) means a transport failure —
//     DNS/TLS/SSRF/connection/timeout; see `error`/`error_detail`.
//   - `ok == true` means the gateway was reached; `status` carries its HTTP
//     status and `rejected_pushkeys` — populated only on a 200 — is the
//     spec's "list of rejected push keys" the caller MUST stop sending to
//     and remove the associated pushers for. This client never touches the
//     database itself; the caller owns acting on the rejection.
struct PushGatewayResult final
{
    bool ok{false};
    bool disabled{false};
    std::uint16_t status{0U};
    std::vector<std::string> rejected_pushkeys{};
    http::OutboundError error{http::OutboundError::network_error};
    std::string error_detail{};
    // The request was not sent because too many were already in flight to this gateway host or
    // address (GatewayInFlightLimiter, F-79). Not a failure of the gateway: the caller retries it.
    bool busy{false};
};

} // namespace merovingian::push
