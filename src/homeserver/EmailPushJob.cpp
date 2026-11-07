// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/EmailPushJob.hpp"

#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/email_push.hpp"
#include "merovingian/push/email_digest_queue.hpp"

#include <chrono>
#include <mutex>

namespace merovingian::homeserver
{

EmailPushJob::EmailPushJob(HomeserverRuntime& runtime)
    : runtime_{runtime}
    , job_{"email-push", [&runtime](StopFlag const& stop) {
               return send_due_email_notifications(runtime, stop, std::chrono::steady_clock::now());
           }}
{
}

EmailPushJob::~EmailPushJob()
{
    stop();
}

auto EmailPushJob::start() -> bool
{
    if (!job_.start())
    {
        return false;
    }
    if (runtime_.email_digest_queue_ != nullptr)
    {
        runtime_.email_digest_queue_->set_wake([this]() {
            job_.wake();
        });
    }
    return true;
}

auto EmailPushJob::stop() noexcept -> void
{
    if (runtime_.email_digest_queue_ != nullptr)
    {
        try
        {
            runtime_.email_digest_queue_->set_wake({});
        }
        catch (...)
        {
            // Clearing a std::function does not throw; set_wake's mutex could, in principle.
        }
    }
    job_.stop();
}

} // namespace merovingian::homeserver
