// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/periodic_job.hpp"

namespace merovingian::homeserver
{

struct HomeserverRuntime;

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
