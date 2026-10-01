// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/http/in_flight_budget.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>

namespace merovingian::homeserver
{

struct HomeserverRuntime;

// The shipped size of the main request pool (server.http.request_threads,
// HTTP-1 / ADR-0077). The running server sizes its pool, and the caps below,
// from the configured value; this default is what a runtime built without a
// configuration uses.
inline constexpr std::uint32_t default_main_request_pool_threads{16U};

// How long the federation-worker round trip may exceed the request's own total
// timeout, for calls with no tighter budget: the worker needs time to hand back
// a result after its transport has timed out.
inline constexpr std::chrono::seconds default_worker_ipc_margin{10};

// Client-triggered outbound proxying (ADR-0079).
//
// Some client requests make this server call another one before answering:
// publicRooms with ?server=, a remote room-alias lookup, a remote media
// download or thumbnail. Several of them are reachable without authentication
// (the spec permits it), and each holds a main-pool thread for the whole
// round trip, so an unbounded number of them lets one attacker-controlled peer
// that never answers stall every other request. Every such call therefore runs
// under this policy: a small in-flight budget, and a short total deadline.
struct ClientOutboundProxyPolicy final
{
    // Calls in flight across every client. Half of the main request pool, so
    // the other half always stays available to requests that never leave this
    // server.
    std::uint32_t global_cap{default_main_request_pool_threads / 2U};
    // Calls in flight for one client address (rate_limit_client_key, which
    // honours trusted_proxies and groups IPv6 by prefix).
    std::uint32_t per_client_cap{1U};
    // Total wall-clock budget for a directory lookup (publicRooms, alias):
    // server discovery plus the request.
    std::uint32_t directory_deadline_seconds{10U};
    // Total wall-clock budget for a remote media fetch: server discovery, the
    // federation media request, and the legacy fallback together.
    std::uint32_t media_deadline_seconds{30U};
    // Slack the federation-worker round trip may add on top of the deadline for
    // the worker to hand its (already timed-out) result back.
    std::uint32_t worker_margin_seconds{2U};
    // Advertised in the 429 answer.
    std::uint32_t retry_after_ms{1000U};
};

// The policy for a request pool of `pool_threads` threads.
[[nodiscard]] constexpr auto client_outbound_proxy_policy_for_pool(std::uint32_t pool_threads) noexcept
    -> ClientOutboundProxyPolicy
{
    auto policy = ClientOutboundProxyPolicy{};
    // Never zero: a zero cap would refuse every remote lookup on a tiny pool.
    policy.global_cap = std::max(1U, pool_threads / 2U);
    return policy;
}

[[nodiscard]] constexpr auto default_client_outbound_proxy_policy() noexcept -> ClientOutboundProxyPolicy
{
    return client_outbound_proxy_policy_for_pool(default_main_request_pool_threads);
}

// A wall-clock deadline fixed when it is constructed. Discovery and each
// request that follows draw from the same one, so a slow first step shortens
// the next rather than adding to it.
class OutboundDeadline final
{
public:
    explicit OutboundDeadline(std::uint32_t budget_seconds) noexcept
        : m_end{std::chrono::steady_clock::now() + std::chrono::seconds{budget_seconds}}
    {
    }

    // Whole seconds left, rounded up so a sub-second remainder still allows a
    // request; 0 once the deadline has passed.
    [[nodiscard]] auto remaining_seconds() const noexcept -> std::uint32_t
    {
        auto const now = std::chrono::steady_clock::now();
        if (now >= m_end)
        {
            return 0U;
        }
        auto const left = std::chrono::duration_cast<std::chrono::milliseconds>(m_end - now).count();
        return static_cast<std::uint32_t>((left + 999) / 1000);
    }

    [[nodiscard]] auto expired() const noexcept -> bool
    {
        return std::chrono::steady_clock::now() >= m_end;
    }

private:
    std::chrono::steady_clock::time_point m_end;
};

// Takes one slot in the runtime's client-outbound budget for `client_key`.
// nullopt means over the global or the per-client cap: answer 429 with
// runtime.client_outbound_proxy_policy.retry_after_ms and make no outbound
// call. Hold the returned slot until the call has finished; it releases on
// every exit path. Take it before releasing the runtime lock.
[[nodiscard]] auto admit_client_outbound_proxy(HomeserverRuntime& runtime,
                                               std::string client_key) -> std::optional<http::InFlightBudget::Slot>;

// `requested_seconds` bounded by the operator's federation remote_timeout when
// that is configured, so this policy only ever shortens a call.
[[nodiscard]] auto effective_client_outbound_deadline(HomeserverRuntime const& runtime,
                                                      std::uint32_t requested_seconds) -> std::uint32_t;

} // namespace merovingian::homeserver
