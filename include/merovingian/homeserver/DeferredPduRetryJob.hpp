// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/periodic_job.hpp"

namespace merovingian::homeserver
{

struct HomeserverRuntime;

// Runs retry_deferred_pdus on its own thread and keeps the runtime's wake hook
// pointing at it. The thread starts only in start(), after process hardening
// (ADR-0082). stop() (and the destructor) clear the hook under
// HomeserverRuntime::mutex before stopping the thread, so no request thread can
// wake a job that no longer exists; call it before the runtime is torn down.
class DeferredPduRetryJob final
{
public:
    explicit DeferredPduRetryJob(HomeserverRuntime& runtime);
    ~DeferredPduRetryJob();

    DeferredPduRetryJob(DeferredPduRetryJob const&) = delete;
    DeferredPduRetryJob(DeferredPduRetryJob&&) = delete;
    auto operator=(DeferredPduRetryJob const&) -> DeferredPduRetryJob& = delete;
    auto operator=(DeferredPduRetryJob&&) -> DeferredPduRetryJob& = delete;

    // Installs the wake hook and starts the thread. False if the thread could
    // not be started (the hook is then left unset).
    [[nodiscard]] auto start() -> bool;
    // Clears the wake hook, then stops and joins the thread. Idempotent.
    auto stop() noexcept -> void;

private:
    HomeserverRuntime& runtime_;
    PeriodicJob job_;
};

} // namespace merovingian::homeserver
