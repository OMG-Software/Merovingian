// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/ClientOutboundProxyPolicy.hpp"
#include "merovingian/homeserver/OutboundDeadline.hpp"
#include "merovingian/homeserver/RuntimeMutex.hpp"
#include "merovingian/http/InFlightBudget.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>

namespace merovingian::homeserver
{

struct HomeserverRuntime;

// How long the federation-worker round trip may exceed the request's own total
// timeout, for calls with no tighter budget: the worker needs time to hand back
// a result after its transport has timed out.
inline constexpr std::chrono::seconds default_worker_ipc_margin{10};

// The policy for a request pool of `pool_threads` threads.
[[nodiscard]] constexpr auto client_outbound_proxy_policy_for_pool(std::uint32_t pool_threads) noexcept
    -> ClientOutboundProxyPolicy
{
    auto policy = ClientOutboundProxyPolicy{};
    // Never zero: a zero cap would refuse every remote lookup on a tiny pool.
    policy.global_cap = std::max(1U, pool_threads / 2U);
    policy.policy_server_global_cap = std::max(2U, pool_threads / 4U);
    policy.policy_server_per_surface_cap = std::max(1U, policy.policy_server_global_cap / 2U);
    return policy;
}

[[nodiscard]] constexpr auto default_client_outbound_proxy_policy() noexcept -> ClientOutboundProxyPolicy
{
    return client_outbound_proxy_policy_for_pool(default_main_request_pool_threads);
}

// Takes one slot in the runtime's client-outbound budget for `client_key`.
// nullopt means over the global or the per-client cap: answer 429 with
// runtime.client_outbound_proxy_policy.retry_after_ms and make no outbound
// call. Hold the returned slot until the call has finished; it releases on
// every exit path. Take it before releasing the runtime lock.
[[nodiscard]] auto admit_client_outbound_proxy(HomeserverRuntime& runtime, std::string client_key)
    -> std::optional<http::InFlightBudget::Slot>;

// ADR-0306: admit_client_outbound_proxy, but waiting for a slot until `deadline` instead of giving up at
// once. runtime.mutex is released (through `guard`) while it sleeps, so a waiting request never blocks
// another; whatever was read from the runtime before the call must be found again after it. Only for an
// authenticated request: the thread it holds while waiting is bounded by the client's connection share
// (ADR-0077) and by the deadline.
[[nodiscard]] auto admit_client_outbound_proxy_waiting(HomeserverRuntime& runtime, std::string const& client_key,
                                                       RuntimeLock& guard,
                                                       OutboundDeadline const& deadline)
    -> std::optional<http::InFlightBudget::Slot>;

// The budget for offering remote invites (ADR-0307): one `POST /invite`, or all of a createRoom's. The
// outbound default total timeout; effective_client_outbound_deadline lowers it to `remote_timeout`.
inline constexpr auto remote_invite_offer_seconds = std::uint32_t{30U};

// `requested_seconds` bounded by the operator's federation remote_timeout when
// that is configured, so this policy only ever shortens a call.
[[nodiscard]] auto effective_client_outbound_deadline(HomeserverRuntime const& runtime, std::uint32_t requested_seconds)
    -> std::uint32_t;

} // namespace merovingian::homeserver
