// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/config/PushConfig.hpp"
#include "merovingian/homeserver/PushRetryJob.hpp" // split-shim
#include "merovingian/homeserver/periodic_job.hpp"
#include "merovingian/homeserver/stop_flag.hpp"
#include "merovingian/push/push_gateway_client.hpp"
#include "merovingian/push/push_retry_queue.hpp"

#include <chrono>
#include <cstddef>

namespace merovingian::homeserver
{

struct HomeserverRuntime;

// R14 (ADR-0206). Spec (push-gateway-api.md): "If the endpoint returns an HTTP error code, the
// homeserver SHOULD retry for a reasonable amount of time using exponential backoff." Failed
// notifications wait in HomeserverRuntime::push_retry_queue_ (in memory, push::PushRetryQueue)
// and one PeriodicJob thread sends them again; a request never waits for a retry.

// At most this many retries are sent by one call of retry_due_push_deliveries, so one call cannot
// hold the job (or a stop request) behind a backlog.
inline constexpr auto push_retry_batch = std::size_t{32U};
// How long the retry job sleeps when nothing is due sooner. Scheduling a retry wakes it.
inline constexpr auto push_retry_idle_delay = std::chrono::minutes{5};
// F-81, ADR-0410: once a call of retry_due_push_deliveries has spent this long it starts no more
// attempts; the retries it has not reached go back to the queue. One account's slow gateway can
// then hold the single retry thread for this and one attempt, not for a whole batch of timeouts.
inline constexpr auto push_retry_batch_budget = std::chrono::seconds{30};
// A retry waits at most this long for the gateway in all, and at most half of it to connect: a
// retry is not what a user is waiting for, and it is the one thread everyone's retries share.
inline constexpr auto push_retry_total_timeout = std::chrono::seconds{10};
inline constexpr auto push_retry_connect_timeout = std::chrono::seconds{5};

// F-79, ADR-0409: a recipient batch stops contacting gateways after this long (twice the total
// timeout) and queues the pushers it has not reached for retry, so the batch's delivery slot is
// held for this and one attempt, not for as many timeouts as the recipient has pushers.
[[nodiscard]] auto push_batch_deadline(config::PushConfig const& config) noexcept -> std::chrono::seconds;

// `config` with the shorter timeouts a retry uses.
[[nodiscard]] auto push_retry_config(config::PushConfig config) noexcept -> config::PushConfig;

// Queues `delivery`, which a batch ran out of time before reaching, to be tried after the first
// backoff. It has not been attempted, so it does not count as a failed attempt.
auto defer_push_delivery(HomeserverRuntime& runtime, push::PushRetry delivery,
                         std::chrono::steady_clock::time_point now) -> void;

// One attempt to deliver `delivery` to its pusher: skipped when the gateway's circuit is open
// (ADR-0151), otherwise sent with `client`. An answer slower than half of the client's total
// timeout counts against the host's circuit like an unreachable gateway (F-79, ADR-0409); a request
// held back by the in-flight cap on its gateway is retried without counting. A pushkey the gateway
// rejects loses its pusher and its
// queued retries. A failure push::push_delivery_should_retry accepts, an open circuit included,
// is counted and scheduled at `now` plus the time the attempt took plus its backoff, or given up
// and logged. Takes
// HomeserverRuntime::mutex only to delete a rejected pusher, never across the network call; call
// it without that mutex held.
auto attempt_push_delivery(HomeserverRuntime& runtime, push::PushGatewayClient& client, push::PushRetry delivery,
                           std::chrono::steady_clock::time_point now) -> void;

// The retry job's body: sends the retries due at `now` (at most push_retry_batch, one recipient's
// at a time in turn, F-81), checking `stop` between them. A retry whose pusher has since been
// removed, or now names another gateway URL, is dropped; so is one whose recipient has been
// deactivated (F-80). A retry that fails again is scheduled from `now` plus the time the batch has
// taken so far. Once `budget` has passed, or `stop` is requested, the retries not yet reached go
// back to the queue unchanged. Returns how long to wait before the next call: until the earliest
// queued retry, measured the same way, between one second and push_retry_idle_delay.
[[nodiscard]] auto retry_due_push_deliveries(HomeserverRuntime& runtime, StopFlag const& stop,
                                             std::chrono::steady_clock::time_point now,
                                             std::chrono::milliseconds budget = push_retry_batch_budget)
    -> std::chrono::milliseconds;

} // namespace merovingian::homeserver
