// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/PeriodicJob.hpp"

namespace merovingian::homeserver
{

struct HomeserverRuntime;

// Runs send_due_email_notifications on its own thread and points the email queue's wake hook at
// it. The thread starts only in start(), after process hardening (ADR-0082). stop() (and the
// destructor) clear the hook before stopping the thread; call it before the runtime is torn down.
class EmailPushJob final
{
public:
    explicit EmailPushJob(HomeserverRuntime& runtime);
    ~EmailPushJob();

    EmailPushJob(EmailPushJob const&) = delete;
    EmailPushJob(EmailPushJob&&) = delete;
    auto operator=(EmailPushJob const&) -> EmailPushJob& = delete;
    auto operator=(EmailPushJob&&) -> EmailPushJob& = delete;

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
