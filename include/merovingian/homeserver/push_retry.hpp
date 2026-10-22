// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

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

// One attempt to deliver `delivery` to its pusher: skipped when the gateway's circuit is open
// (ADR-0151), otherwise sent with `client`. A pushkey the gateway rejects loses its pusher and its
// queued retries. A failure push::push_delivery_should_retry accepts, an open circuit included,
// is counted and scheduled at `now` plus its backoff, or given up and logged. Takes
// HomeserverRuntime::mutex only to delete a rejected pusher, never across the network call; call
// it without that mutex held.
auto attempt_push_delivery(HomeserverRuntime& runtime, push::PushGatewayClient& client, push::PushRetry delivery,
                           std::chrono::steady_clock::time_point now) -> void;

// The retry job's body: sends the retries due at `now` (at most push_retry_batch), checking `stop`
// between them. A retry whose pusher has since been removed, or now names another gateway URL, is
// dropped. A retry that fails again is scheduled from `now` plus the time the batch has taken so
// far. Returns how long to wait before the next call: until the earliest queued retry, measured
// the same way, between one second and push_retry_idle_delay.
[[nodiscard]] auto retry_due_push_deliveries(HomeserverRuntime& runtime, StopFlag const& stop,
                                             std::chrono::steady_clock::time_point now) -> std::chrono::milliseconds;

// Runs retry_due_push_deliveries on its own thread and points the retry queue's wake hook at it,
// so a newly scheduled retry is noticed at once. The thread starts only in start(), after process
// hardening (ADR-0082). stop() (and the destructor) clear the hook before stopping the thread, so
// no delivery task can wake a job that no longer exists; call it before the runtime is torn down.
class PushRetryJob final
{
public:
    explicit PushRetryJob(HomeserverRuntime& runtime);
    ~PushRetryJob();

    PushRetryJob(PushRetryJob const&) = delete;
    PushRetryJob(PushRetryJob&&) = delete;
    auto operator=(PushRetryJob const&) -> PushRetryJob& = delete;
    auto operator=(PushRetryJob&&) -> PushRetryJob& = delete;

    // Starts the thread and installs the wake hook. False if the thread could not be started (the
    // hook is then left unset).
    [[nodiscard]] auto start() -> bool;
    // Clears the wake hook, then stops and joins the thread. Idempotent.
    auto stop() noexcept -> void;

private:
    HomeserverRuntime& runtime_;
    PeriodicJob job_;
};

} // namespace merovingian::homeserver
