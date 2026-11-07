// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::push
{

// What a delivery says about whether its gateway host can be reached
// (OUT-3, ADR-0151). Only `transport_failure` counts toward opening the host's
// circuit: any HTTP answer, a 5xx or 429 included, is about one notification,
// and a host shared by many users must not be closed to all of them by one
// user's pusher. `not_attempted` (delivery disabled, a URL or response this
// server refused, or a request held back by GatewayInFlightLimiter) neither
// counts nor resets. `slow_answer` is an HTTP answer that took more than half
// the total timeout (F-79, ADR-0409): it counts toward the circuit like a
// transport failure, because a gateway answering just inside the timeout holds
// a delivery slot as long as one that never answers, and unlike a 5xx, one
// user's pusher data cannot easily make a shared host slow.
enum class GatewayCircuitOutcome : std::uint8_t
{
    reachable,
    transport_failure,
    not_attempted,
    slow_answer,
};

} // namespace merovingian::push
