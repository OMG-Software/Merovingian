// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <condition_variable>
#include <functional>
#include <mutex>
#include <queue>
#include <stop_token>
#include <thread>
#include <vector>

namespace merovingian::net
{

// Bounded work queue with a fixed pool of jthread workers. Listener threads
// submit work items (typically request-handling lambdas); workers dequeue and
// execute them concurrently. Graceful shutdown is initiated by request_stop()
// or by destroying the pool — workers finish their current work item before
// exiting.
class ThreadPool final
{
public:
    explicit ThreadPool(std::size_t worker_count);
    ThreadPool(ThreadPool const&) = delete;
    auto operator=(ThreadPool const&) -> ThreadPool& = delete;
    ThreadPool(ThreadPool&&) = delete;
    auto operator=(ThreadPool&&) -> ThreadPool& = delete;
    ~ThreadPool();

    // Enqueue a work item. The callable is invoked by the next available
    // worker. Safe to call from any thread (including listener threads).
    auto submit(std::function<void()> work) -> void;

    // Signal all workers to stop after finishing their current work item.
    // No new submissions are accepted after this call.
    auto request_stop() -> void;

    // Query whether the pool is still accepting work.
    [[nodiscard]] auto running() const -> bool;

private:
    auto worker_loop(std::stop_token stop) -> void;

    mutable std::mutex queue_mutex_{};
    std::condition_variable queue_cv_{};
    std::queue<std::function<void()>> queue_{};
    bool stopping_{false};
    std::vector<std::jthread> workers_{};
};

} // namespace merovingian::net