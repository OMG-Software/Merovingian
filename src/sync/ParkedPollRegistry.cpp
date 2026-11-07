// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/sync/ParkedPollRegistry.hpp"

#include "merovingian/sync/ParkOutcome.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
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
namespace
{

    [[nodiscard]] auto refused(std::string message) -> ParkOutcome
    {
        return ParkOutcome{false, 0U, std::move(message)};
    }

} // namespace

ParkedPollRegistry::~ParkedPollRegistry()
{
    request_stop();
}

auto ParkedPollRegistry::start(ParkedPollLimits limits, ResumeFn resume) -> bool
{
    auto lock = std::lock_guard{m_mutex};
    if (m_started || m_stopping || !resume)
    {
        return false;
    }
    m_limits = limits;
    m_resume = std::move(resume);
    m_started = true;
    m_thread = std::thread{[this] {
        run();
    }};
    return true;
}

auto ParkedPollRegistry::request_stop() -> void
{
    // Polls are destroyed after the lock is gone: destroying one closes a socket and releases budgets.
    auto doomed = std::vector<std::unique_ptr<ParkedPoll>>{};
    {
        auto lock = std::lock_guard{m_mutex};
        m_stopping = true;
        for (auto& entry : m_entries)
        {
            doomed.push_back(std::move(entry.second.poll));
        }
        for (auto& ready : m_ready)
        {
            doomed.push_back(std::move(ready.poll));
        }
        m_entries.clear();
        m_by_user.clear();
        m_deadlines.clear();
        m_ready.clear();
    }
    m_signal.notify_all();
    // Only the first caller finds the thread joinable; a second caller waits on nothing.
    if (m_thread.joinable() && m_thread.get_id() != std::this_thread::get_id())
    {
        m_thread.join();
    }
    doomed.clear();
}

auto ParkedPollRegistry::running() const -> bool
{
    auto lock = std::lock_guard{m_mutex};
    return m_started && !m_stopping;
}

auto ParkedPollRegistry::park(std::string_view user, std::chrono::steady_clock::time_point deadline,
                              std::unique_ptr<ParkedPoll>& poll) -> ParkOutcome
{
    if (poll == nullptr)
    {
        return refused("no poll to park");
    }
    auto lock = std::lock_guard{m_mutex};
    if (!m_started || m_stopping)
    {
        return refused("parking is not running");
    }
    if (m_entries.size() >= m_limits.max_parked)
    {
        return refused("too many parked long-polls");
    }
    auto by_user = m_by_user.find(std::string{user});
    if (by_user != m_by_user.end() && by_user->second.size() >= m_limits.max_parked_per_user)
    {
        return refused("too many parked long-polls for this user");
    }
    auto const ticket = m_next_ticket++;
    if (by_user == m_by_user.end())
    {
        by_user = m_by_user.try_emplace(std::string{user}).first;
    }
    by_user->second.push_back(ticket);
    auto const deadline_it = m_deadlines.emplace(deadline, ticket);
    m_entries.emplace(ticket, Entry{std::string{user}, deadline_it, std::move(poll)});
    // The thread may be sleeping past this deadline.
    m_signal.notify_all();
    return ParkOutcome{true, ticket, {}};
}

auto ParkedPollRegistry::make_ready_locked(std::unordered_map<std::uint64_t, Entry>::iterator entry, WakeReason reason)
    -> void
{
    auto const ticket = entry->first;
    m_deadlines.erase(entry->second.deadline_it);
    auto by_user = m_by_user.find(entry->second.user);
    if (by_user != m_by_user.end())
    {
        std::erase(by_user->second, ticket);
        if (by_user->second.empty())
        {
            m_by_user.erase(by_user);
        }
    }
    m_ready.push_back(Ready{std::move(entry->second.poll), reason});
    m_entries.erase(entry);
}

auto ParkedPollRegistry::wake_users(std::span<std::string const> users) -> void
{
    auto woke = false;
    {
        auto lock = std::lock_guard{m_mutex};
        if (m_entries.empty())
        {
            return;
        }
        for (auto const& user : users)
        {
            auto const by_user = m_by_user.find(user);
            if (by_user == m_by_user.end())
            {
                continue;
            }
            // make_ready_locked edits this list; take a copy (bounded by the per-user cap).
            auto const tickets = by_user->second;
            for (auto const ticket : tickets)
            {
                auto const entry = m_entries.find(ticket);
                if (entry != m_entries.end())
                {
                    make_ready_locked(entry, WakeReason::published);
                    woke = true;
                }
            }
        }
    }
    if (woke)
    {
        m_signal.notify_all();
    }
}

auto ParkedPollRegistry::wake_all() -> void
{
    {
        auto lock = std::lock_guard{m_mutex};
        if (m_entries.empty())
        {
            return;
        }
        for (auto& entry : m_entries)
        {
            m_ready.push_back(Ready{std::move(entry.second.poll), WakeReason::published});
        }
        m_entries.clear();
        m_by_user.clear();
        m_deadlines.clear();
    }
    m_signal.notify_all();
}

auto ParkedPollRegistry::wake(std::uint64_t ticket) -> void
{
    {
        auto lock = std::lock_guard{m_mutex};
        auto const entry = m_entries.find(ticket);
        if (entry == m_entries.end())
        {
            return;
        }
        make_ready_locked(entry, WakeReason::published);
    }
    m_signal.notify_all();
}

auto ParkedPollRegistry::parked() const -> std::size_t
{
    auto lock = std::lock_guard{m_mutex};
    return m_entries.size();
}

auto ParkedPollRegistry::parked_for(std::string_view user) const -> std::size_t
{
    auto lock = std::lock_guard{m_mutex};
    auto const by_user = m_by_user.find(std::string{user});
    return by_user == m_by_user.end() ? std::size_t{0U} : by_user->second.size();
}

// The registry thread: expire deadlines, then hand every ready poll to the resume callback with no lock held.
auto ParkedPollRegistry::run() -> void
{
    auto lock = std::unique_lock{m_mutex};
    while (!m_stopping)
    {
        auto const now = std::chrono::steady_clock::now();
        while (!m_deadlines.empty() && m_deadlines.begin()->first <= now)
        {
            auto const entry = m_entries.find(m_deadlines.begin()->second);
            make_ready_locked(entry, WakeReason::deadline);
        }
        if (!m_ready.empty())
        {
            auto batch = std::vector<Ready>{};
            batch.swap(m_ready);
            lock.unlock(); // LOCK_RELEASE: reviewed - the resume callback never runs under the registry mutex
            for (auto& ready : batch)
            {
                try
                {
                    m_resume(std::move(ready.poll), ready.reason);
                }
                catch (...)
                {
                    // A resume that throws drops its poll (closing the connection); the thread must survive.
                }
                ready.poll.reset();
            }
            batch.clear();
            lock.lock(); // LOCK_RELEASE: reviewed - re-taken after the batch
            continue;
        }
        if (m_deadlines.empty())
        {
            // Every notify follows one of these three changes; a spurious wake-up finds none and sleeps again.
            m_signal.wait(lock, [this] {
                return m_stopping || !m_ready.empty() || !m_deadlines.empty();
            });
        }
        else
        {
            // A copy, never m_deadlines.begin()->first: wait_until holds its time point by reference and reads it again
            // on waking, and wake_users / stop erase that node while this thread waits.
            auto const next_deadline = m_deadlines.begin()->first;
            m_signal.wait_until(lock, next_deadline);
        }
    }
}

} // namespace merovingian::sync
