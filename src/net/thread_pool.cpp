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
    for (auto i = std::size_t{0U}; i < worker_count; ++i)
    {
        workers_.emplace_back([this](std::stop_token stop) { worker_loop(stop); });
    }
    log_diagnostic("pool.started", {{"workers", std::to_string(worker_count), false}});
}

ThreadPool::~ThreadPool()
{
    request_stop();
}

auto ThreadPool::submit(std::function<void()> work) -> void
{
    {
        auto lock = std::lock_guard{queue_mutex_};
        if (stopping_)
        {
            return;
        }
        queue_.push(std::move(work));
    }
    queue_cv_.notify_one();
}

auto ThreadPool::request_stop() -> void
{
    {
        auto lock = std::lock_guard{queue_mutex_};
        stopping_ = true;
    }
    queue_cv_.notify_all();
    for (auto& worker : workers_)
    {
        worker.request_stop();
    }
}

auto ThreadPool::running() const -> bool
{
    auto lock = std::lock_guard{queue_mutex_};
    return !stopping_;
}

auto ThreadPool::worker_loop(std::stop_token stop) -> void
{
    while (!stop.stop_requested())
    {
        auto work = std::function<void()>{};
        {
            auto lock = std::unique_lock{queue_mutex_};
            queue_cv_.wait(lock, [this, &stop] {
                return stopping_ || !queue_.empty() || stop.stop_requested();
            });
            if ((stopping_ && queue_.empty()) || stop.stop_requested())
            {
                break;
            }
            if (queue_.empty())
            {
                continue;
            }
            work = std::move(queue_.front());
            queue_.pop();
        }
        if (work)
        {
            work();
        }
    }
}

} // namespace merovingian::net