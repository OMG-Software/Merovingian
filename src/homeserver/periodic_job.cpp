// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "merovingian/homeserver/periodic_job.hpp"

#include "merovingian/observability/logger.hpp"

#include <exception>
#include <string>
#include <system_error>
#include <tuple>
#include <utility>

namespace merovingian::homeserver
{

namespace
{

    // Delay after a run that threw: long enough not to spin on a persistent
    // fault, short enough that a transient one does not stall the queue.
    constexpr auto delay_after_failure = std::chrono::milliseconds{5000};

} // namespace

PeriodicJob::PeriodicJob(std::string name, Job job)
    : name_{std::move(name)}
    , job_{std::move(job)}
{
}

PeriodicJob::~PeriodicJob()
{
    stop();
}

auto PeriodicJob::start() -> bool
{
    if (thread_.joinable() || !job_)
    {
        return false;
    }
    try
    {
        thread_ = std::jthread{[this](std::stop_token const& stop) {
            run(stop);
        }};
    }
    catch (std::system_error const&)
    {
        return false;
    }
    return true;
}

auto PeriodicJob::wake() noexcept -> void
{
    {
        auto const guard = std::lock_guard{mutex_};
        woken_ = true;
    }
    wake_condition_.notify_one();
}

auto PeriodicJob::stop() noexcept -> void
{
    if (!thread_.joinable())
    {
        return;
    }
    thread_.request_stop();
    thread_.join();
}

auto PeriodicJob::running() const noexcept -> bool
{
    return thread_.joinable();
}

auto PeriodicJob::run(std::stop_token const& stop) -> void
{
    while (!stop.stop_requested())
    {
        auto delay = delay_after_failure;
        try
        {
            delay = job_(stop);
        }
        catch (std::exception const& error)
        {
            LOG_WARNING("Background job " + name_ + " failed: " + std::string{error.what()});
        }
        catch (...)
        {
            LOG_WARNING("Background job " + name_ + " failed with an unknown exception");
        }

        auto lock = std::unique_lock{mutex_};
        // Returns early on wake() or stop; a wake that arrived during the run
        // above is already recorded in woken_ and skips the wait entirely.
        std::ignore = wake_condition_.wait_for(lock, stop, delay, [this]() {
            return woken_;
        });
        woken_ = false;
    }
}

} // namespace merovingian::homeserver
