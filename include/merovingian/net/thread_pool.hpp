// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <condition_variable>
#include <functional>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

namespace merovingian::net
{

// Unbounded work queue with a fixed pool of std::thread workers. Listener threads
// submit work items (typically request-handling lambdas); workers dequeue and
// execute them concurrently. Graceful shutdown is initiated by request_stop()
// or by destroying the pool — workers drain the queue before exiting. All
// threads are joined on destruction.
class ThreadPool final
{
public:
    explicit ThreadPool(std::size_t worker_count);
    ThreadPool(ThreadPool const&) = delete;
    auto operator=(ThreadPool const&) -> ThreadPool& = delete;
    ThreadPool(ThreadPool&&) = delete;
    auto operator=(ThreadPool&&) -> ThreadPool& = delete;
    ~ThreadPool();

    // Enqueue a work item. Returns true if the work was enqueued, false if
    // the pool has been stopped (the callable is discarded). Safe to call
    // from any thread (including listener threads).
    [[nodiscard]] auto submit(std::function<void()> work) -> bool;

    // Signal all workers to stop after draining the queue. No new submissions
    // are accepted after this call. Blocks until all workers have exited.
    auto request_stop() -> void;

    // Query whether the pool is still accepting work.
    [[nodiscard]] auto running() const -> bool;

private:
    auto worker_loop() -> void;

    mutable std::mutex queue_mutex_{};
    std::condition_variable queue_cv_{};
    std::queue<std::function<void()>> queue_{};
    bool stopping_{false};
    std::vector<std::thread> workers_{};
};

} // namespace merovingian::net