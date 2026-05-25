// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/net/thread_pool.hpp"

#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"

#include <string>
#include <vector>

namespace merovingian::net
{

namespace
{

auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields) -> void
{
    LOG_DEBUG(observability::diagnostic_log_summary("thread_pool", event, std::move(fields)));
}

} // namespace

ThreadPool::ThreadPool(std::size_t worker_count)
{
    workers_.reserve(worker_count);
    try
    {
        for (auto i = std::size_t{0U}; i < worker_count; ++i)
        {
            workers_.emplace_back([this] { worker_loop(); });
        }
    }
    catch (...)
    {
        // Join all threads that were successfully created before rethrowing.
        // Without this, joinable threads would call std::terminate on destruction.
        request_stop();
        throw;
    }
    log_diagnostic("pool.started", {{"workers", std::to_string(worker_count), false}});
}

ThreadPool::~ThreadPool()
{
    request_stop();
}

auto ThreadPool::submit(std::function<void()> work) -> bool
{
    {
        auto lock = std::lock_guard{queue_mutex_};
        if (stopping_)
        {
            log_diagnostic("submit.dropped", {{"reason", "pool_stopped", false}});
            return false;
        }
        queue_.push(std::move(work));
    }
    queue_cv_.notify_one();
    return true;
}

auto ThreadPool::request_stop() -> void
{
    {
        auto lock = std::lock_guard{queue_mutex_};
        if (stopping_)
        {
            return;
        }
        stopping_ = true;
    }
    queue_cv_.notify_all();
    for (auto& worker : workers_)
    {
        if (worker.joinable())
        {
            worker.join();
        }
    }
}

auto ThreadPool::running() const -> bool
{
    auto lock = std::lock_guard{queue_mutex_};
    return !stopping_;
}

auto ThreadPool::worker_loop() -> void
{
    while (true)
    {
        auto work = std::function<void()>{};
        {
            auto lock = std::unique_lock{queue_mutex_};
            queue_cv_.wait(lock, [this] { return stopping_ || !queue_.empty(); });
            if (stopping_ && queue_.empty())
            {
                return;
            }
            // stopping_ is true and queue is non-empty: drain remaining items.
            work = std::move(queue_.front());
            queue_.pop();
        }
        try
        {
            work();
        }
        catch (...)
        {
            log_diagnostic("worker.exception", {{"action", "swallowed", false}});
        }
    }
}

} // namespace merovingian::net