// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/PushRetryJob.hpp"

#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/push_retry.hpp"

#include <chrono>
#include <mutex>

namespace merovingian::homeserver
{

PushRetryJob::PushRetryJob(HomeserverRuntime& runtime)
    : runtime_{runtime}
    , job_{"push-retry", [&runtime](StopFlag const& stop) {
               return retry_due_push_deliveries(runtime, stop, std::chrono::steady_clock::now());
           }}
{
}

PushRetryJob::~PushRetryJob()
{
    stop();
}

auto PushRetryJob::start() -> bool
{
    if (!job_.start())
    {
        return false;
    }
    if (runtime_.push_retry_queue_ != nullptr)
    {
        runtime_.push_retry_queue_->set_wake([this]() {
            job_.wake();
        });
    }
    return true;
}

auto PushRetryJob::stop() noexcept -> void
{
    if (runtime_.push_retry_queue_ != nullptr)
    {
        try
        {
            runtime_.push_retry_queue_->set_wake({});
        }
        catch (...)
        {
            // Clearing a std::function does not throw; set_wake's mutex could, in principle.
        }
    }
    job_.stop();
}

} // namespace merovingian::homeserver
