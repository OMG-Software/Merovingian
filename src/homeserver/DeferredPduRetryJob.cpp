// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/DeferredPduRetryJob.hpp"

#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/deferred_pdu_retry.hpp"

#include <chrono>
#include <mutex>

namespace merovingian::homeserver
{

DeferredPduRetryJob::DeferredPduRetryJob(HomeserverRuntime& runtime)
    : runtime_{runtime}
    , job_{"deferred-pdu-retry", [&runtime](StopFlag const& stop) {
               return retry_deferred_pdus(runtime, stop);
           }}
{
}

DeferredPduRetryJob::~DeferredPduRetryJob()
{
    stop();
}

auto DeferredPduRetryJob::start() -> bool
{
    {
        auto const guard = RuntimeLock{runtime_.mutex};
        runtime_.deferred_pdu_retry_wake = [this]() {
            job_.wake();
        };
    }
    if (!job_.start())
    {
        stop();
        return false;
    }
    return true;
}

auto DeferredPduRetryJob::stop() noexcept -> void
{
    {
        auto const guard = RuntimeLock{runtime_.mutex};
        runtime_.deferred_pdu_retry_wake = nullptr;
    }
    job_.stop();
}

} // namespace merovingian::homeserver
