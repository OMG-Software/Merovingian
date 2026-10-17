// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <chrono>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <stop_token>
#include <string>
#include <thread>

namespace merovingian::homeserver
{

// Runs one job on a dedicated thread: once when started, again whenever
// wake() is called, and otherwise after the delay the job's previous run
// returned. Used for work that must not ride on a client request: draining the
// appservice transaction queue and retrying deferred federation PDUs.
//
// One thread per job, so the job body never runs concurrently with itself.
// That is what lets a job own a queue's single-consumer invariants (one
// in-flight appservice transaction per appservice) without a lock of its own.
//
// The thread starts only in start(), never in the constructor: no thread may
// start before process hardening (ADR-0082), and tests drive the job body
// directly without a thread. A job that throws is logged and re-run after its
// last requested delay; the thread does not die.
//
// The destructor stops and joins. A job body that is mid-call when stop() runs
// finishes that call first, so a job must bound every blocking call it makes
// (every outbound call it makes carries its own timeout).
class PeriodicJob final
{
public:
    // Returns how long to wait before the next run when nobody wakes the job.
    // The stop token is the thread's: a job that loops over a queue checks it
    // between items so shutdown never waits for a whole backlog to drain.
    using Job = std::function<std::chrono::milliseconds(std::stop_token const&)>;

    PeriodicJob(std::string name, Job job);
    ~PeriodicJob();

    PeriodicJob(PeriodicJob const&) = delete;
    PeriodicJob(PeriodicJob&&) = delete;
    auto operator=(PeriodicJob const&) -> PeriodicJob& = delete;
    auto operator=(PeriodicJob&&) -> PeriodicJob& = delete;

    // Starts the thread. False if it could not be created, or was already
    // started. Call only after process hardening (ADR-0082).
    [[nodiscard]] auto start() -> bool;

    // Asks for a run as soon as the current one (if any) ends. Wakes that
    // arrive during a run are not lost: the job runs once more afterwards.
    // Safe from any thread, including while holding HomeserverRuntime::mutex.
    auto wake() noexcept -> void;

    // Requests stop and joins the thread. Idempotent.
    auto stop() noexcept -> void;

    [[nodiscard]] auto running() const noexcept -> bool;

private:
    auto run(std::stop_token const& stop) -> void;

    std::string name_;
    Job job_;
    std::mutex mutex_{};
    std::condition_variable_any wake_condition_{};
    bool woken_{false};
    std::jthread thread_{};
};

} // namespace merovingian::homeserver
