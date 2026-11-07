// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/core/Error.hpp"
#include "merovingian/sync/ParkedPoll.hpp"
#include "merovingian/sync/ParkedPollLimits.hpp"
#include "merovingian/sync/WakeReason.hpp"

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

namespace merovingian::sync
{

// Holds long-polls that have nothing to return, without a thread each (ADR-0569).
//
// Ownership: a parked poll is owned by the registry from a successful park() until it is handed to the resume
// callback (on the registry thread, no lock held) or destroyed at request_stop().
//
// Threading and lock order: one mutex, a leaf. While holding it the registry edits its own containers and signals
// its own condition variable. It never destroys a poll, calls the resume callback, takes any other lock or runs a
// request, so a publisher may call wake_*() while holding HomeserverRuntime::mutex. One thread (start()) resumes
// woken polls and expires deadlines; every deadline is kept in one ordered map.
class ParkedPollRegistry final
{
public:
    // Runs on the registry thread with no lock held; it owns the poll. Dropping it closes the connection.
    using ResumeFn = std::function<void(std::unique_ptr<ParkedPoll>, WakeReason)>;

    ParkedPollRegistry() = default;
    ParkedPollRegistry(ParkedPollRegistry const&) = delete;
    auto operator=(ParkedPollRegistry const&) -> ParkedPollRegistry& = delete;
    ParkedPollRegistry(ParkedPollRegistry&&) = delete;
    auto operator=(ParkedPollRegistry&&) -> ParkedPollRegistry& = delete;
    // Stops the thread and destroys every parked poll.
    ~ParkedPollRegistry();

    // Starts the thread. False when already started or stopped. No thread may start before hardening (ADR-0082).
    [[nodiscard]] auto start(ParkedPollLimits limits, ResumeFn resume) -> bool;

    // Refuses later parks, takes every parked and ready poll, joins the thread, then destroys the polls with no
    // lock held. Idempotent; never call it from the resume callback.
    auto request_stop() -> void;

    [[nodiscard]] auto running() const -> bool;

    // Parks `poll` for `user` until `deadline`. On success the poll is moved from and the result is its ticket; on
    // refusal (not started, stopped, full, or the user is at its cap) `poll` is untouched and still the caller's.
    [[nodiscard]] auto park(std::string_view user, std::chrono::steady_clock::time_point deadline,
                            std::unique_ptr<ParkedPoll>& poll) -> std::expected<std::uint64_t, core::Error>;

    // Resume every parked poll of the named users / of everyone / the one with `ticket` (a no-op when it is no
    // longer parked). They are resumed on the registry thread, never on the caller.
    auto wake_users(std::span<std::string const> users) -> void;
    auto wake_all() -> void;
    auto wake(std::uint64_t ticket) -> void;

    [[nodiscard]] auto parked() const -> std::size_t;
    [[nodiscard]] auto parked_for(std::string_view user) const -> std::size_t;

private:
    struct Entry final
    {
        std::string user{};
        std::multimap<std::chrono::steady_clock::time_point, std::uint64_t>::iterator deadline_it{};
        std::unique_ptr<ParkedPoll> poll{};
    };
    struct Ready final
    {
        std::unique_ptr<ParkedPoll> poll{};
        WakeReason reason{WakeReason::published};
    };

    auto run() -> void;
    // Callers hold m_mutex.
    auto make_ready_locked(std::unordered_map<std::uint64_t, Entry>::iterator entry, WakeReason reason) -> void;

    mutable std::mutex m_mutex{};
    std::condition_variable m_signal{};
    ResumeFn m_resume{};
    ParkedPollLimits m_limits{};
    bool m_started{false};
    bool m_stopping{false};
    std::uint64_t m_next_ticket{1U};
    std::unordered_map<std::uint64_t, Entry> m_entries{};
    std::unordered_map<std::string, std::vector<std::uint64_t>> m_by_user{};
    std::multimap<std::chrono::steady_clock::time_point, std::uint64_t> m_deadlines{};
    std::vector<Ready> m_ready{};
    std::thread m_thread{};
};

} // namespace merovingian::sync
