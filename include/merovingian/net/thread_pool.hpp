// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <condition_variable>
#include <cstddef>
#include <functional>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

namespace merovingian::net
{

// Work queue with a fixed pool of std::thread workers. Listener threads submit
// work items (typically request-handling lambdas); workers dequeue and execute
// them concurrently. Graceful shutdown is initiated by request_stop() or by
// destroying the pool — workers drain the queue before exiting. All threads are
// joined on destruction.
//
// The queue is optionally bounded (0.12.5 audit, finding 11): a pool fed
// directly by an accept loop must have a cap, because one closure is queued per
// accepted connection and an unbounded queue turns a connection flood into an
// OOM kill. Pools that are not network-facing — the IPC dispatch pools, whose
// producers are the local supervisor rather than a remote peer — keep the
// unbounded default, since dropping a message there would silently lose
// federation work rather than shed a connection the peer can retry.
class ThreadPool final
{
public:
    // `on_thread_start`, when set, runs once on each worker thread before it
    // begins dequeuing work — e.g. to install a thread_local resource that
    // callbacks running on that thread will need (see homeserver/AGENTS.md's
    // audit-sink installation, #420). The callback itself must not throw or
    // re-enter the pool.
    //
    // `max_queue_depth` is the maximum number of *waiting* items; 0 means
    // unbounded. Work already picked up by a worker does not count towards it,
    // so a pool of N workers with depth D can have N + D items in flight.
    explicit ThreadPool(std::size_t worker_count, std::function<void()> on_thread_start = {},
                        std::size_t max_queue_depth = 0U);
    ThreadPool(ThreadPool const&) = delete;
    auto operator=(ThreadPool const&) -> ThreadPool& = delete;
    ThreadPool(ThreadPool&&) = delete;
    auto operator=(ThreadPool&&) -> ThreadPool& = delete;
    ~ThreadPool();

    // Enqueue a work item. Returns true if the work was enqueued, false if the
    // pool has been stopped or its queue is already at max_queue_depth (in both
    // cases the callable is discarded). Safe to call from any thread (including
    // listener threads).
    //
    // Callers must handle false as backpressure, not as an error to ignore: an
    // accept loop closes the connection whose closure was refused, which sheds
    // load in the one way a client can see and retry.
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
    std::size_t max_queue_depth_{0U};
    std::function<void()> on_thread_start_{};
    std::vector<std::thread> workers_{};
};

} // namespace merovingian::net