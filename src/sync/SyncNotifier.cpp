// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/sync/SyncNotifier.hpp"

#include "merovingian/observability/LogEventSeverity.hpp"
#include "merovingian/observability/SingleLog.hpp"
#include "merovingian/observability/StructuredLogField.hpp"
#include "merovingian/sync/LongPollOutcome.hpp"
#include "merovingian/sync/LongPollStep.hpp"
#include "merovingian/sync/WaitCursor.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::sync
{
namespace
{

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields,
                        observability::LogEventSeverity severity = observability::LogEventSeverity::debug) -> void
    {
        observability::log_diagnostic("sync_notifier", event, fields, severity);
    }

} // namespace

auto SyncNotifier::publish(std::uint64_t new_stream_ordering, std::uint64_t new_sync_stream_id,
                           std::optional<AffectedUsers> scope) -> void
{
    auto changed = false;
    {
        auto lock = std::lock_guard{mutex_};
        if (new_stream_ordering > stream_ordering_)
        {
            stream_ordering_ = new_stream_ordering;
            changed = true;
        }
        if (new_sync_stream_id > sync_stream_id_)
        {
            sync_stream_id_ = new_sync_stream_id;
            changed = true;
        }
        // The generations move and the waiters are signalled in the hold that moved the counters, so a waiter
        // either saw them at entry or is signalled here (ADR-0437). They move whether or not the positions
        // advanced: a caller publishes the visible position read at publish time, which can equal the position
        // an earlier publish carried for another writer's event.
        if (changed && waiting_anyone_ > 0U)
        {
            ++signals_sent_;
            anyone_.notify_all();
        }
        if (!scope.has_value())
        {
            ++broadcast_generation_;
            for (auto& entry : by_user_)
            {
                if (entry.second.waiters > 0U)
                {
                    ++signals_sent_;
                    entry.second.wake.notify_all();
                }
            }
        }
        else
        {
            for (auto const& user : *scope)
            {
                // A user with no entry has never observed: there is no cursor to miss this publish.
                auto const waiters = by_user_.find(user);
                if (waiters == by_user_.end())
                {
                    continue;
                }
                ++waiters->second.generation;
                if (waiters->second.waiters > 0U)
                {
                    ++signals_sent_;
                    waiters->second.wake.notify_all();
                }
            }
        }
    }
    // After mutex_ is released: the registry's mutex is a leaf and never nests with it (ADR-0569).
    if (scope.has_value())
    {
        parked_.wake_users(*scope);
    }
    else
    {
        parked_.wake_all();
    }
    if (changed)
    {
        log_diagnostic("stream.published", {
                                               {"stream_ordering", std::to_string(new_stream_ordering),  false},
                                               {"sync_stream_id",  std::to_string(new_sync_stream_id),   false},
                                               {"scoped",          scope.has_value() ? "true" : "false", false}
        });
    }
}

auto SyncNotifier::wait_for_change(std::uint64_t since_stream_ordering, std::uint64_t since_sync_stream_id,
                                   std::chrono::milliseconds timeout) -> bool
{
    auto lock = std::unique_lock{mutex_};
    if (stream_ordering_ > since_stream_ordering || sync_stream_id_ > since_sync_stream_id)
    {
        log_diagnostic("stream.changed_immediate",
                       {
                           {"since_stream_ordering", std::to_string(since_stream_ordering), false},
                           {"since_sync_stream_id",  std::to_string(since_sync_stream_id),  false},
                           {"stream_ordering",       std::to_string(stream_ordering_),      false},
                           {"sync_stream_id",        std::to_string(sync_stream_id_),       false}
        });
        return true;
    }
    if (timeout.count() <= 0)
    {
        return false;
    }
    ++waiting_;
    ++waiting_anyone_;
    auto const changed = anyone_.wait_for(lock, timeout, [this, since_stream_ordering, since_sync_stream_id] {
        return stream_ordering_ > since_stream_ordering || sync_stream_id_ > since_sync_stream_id;
    });
    --waiting_anyone_;
    --waiting_;
    log_diagnostic(changed ? "stream.changed" : "stream.timeout",
                   {
                       {"since_stream_ordering", std::to_string(since_stream_ordering), false},
                       {"since_sync_stream_id",  std::to_string(since_sync_stream_id),  false},
                       {"stream_ordering",       std::to_string(stream_ordering_),      false},
                       {"sync_stream_id",        std::to_string(sync_stream_id_),       false},
                       {"timeout_ms",            std::to_string(timeout.count()),       false}
    });
    return changed;
}

auto SyncNotifier::observe(std::string_view user) -> WaitCursor
{
    auto lock = std::lock_guard{mutex_};
    auto entry = by_user_.find(user);
    if (entry == by_user_.end())
    {
        entry = by_user_.try_emplace(std::string{user}).first;
    }
    return WaitCursor{std::string{user}, entry->second.generation, broadcast_generation_};
}

auto SyncNotifier::wait_for_change(WaitCursor const& cursor, std::chrono::milliseconds timeout) -> bool
{
    auto lock = std::unique_lock{mutex_};
    auto entry = by_user_.find(cursor.user);
    if (entry == by_user_.end())
    {
        entry = by_user_.try_emplace(cursor.user).first;
    }
    auto& user = entry->second;
    auto const moved = [this, &user, &cursor] {
        return user.generation != cursor.user_generation || broadcast_generation_ != cursor.broadcast_generation;
    };
    if (moved())
    {
        return true;
    }
    if (timeout.count() <= 0)
    {
        return false;
    }
    ++waiting_;
    ++user.waiters;
    auto const changed = user.wake.wait_for(lock, timeout, moved);
    --user.waiters;
    --waiting_;
    return changed;
}

auto long_poll_wait(SyncNotifier& notifier, std::string_view user, std::uint64_t since_stream_ordering,
                    std::uint64_t since_sync_stream_id, std::chrono::steady_clock::time_point deadline,
                    std::chrono::milliseconds slice, std::function<bool()> const& running,
                    std::function<LongPollStep()> const& rerun, std::function<bool()> const& idle) -> LongPollOutcome
{
    auto outcome = LongPollOutcome{};
    auto const run = [&] {
        auto const step = rerun();
        since_stream_ordering = step.since_stream_ordering;
        since_sync_stream_id = step.since_sync_stream_id;
        outcome.dispatched = step.complete;
        return step.complete;
    };
    auto const remaining_slice = [&] {
        auto const remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
        return std::min(remaining, slice);
    };
    if (user.empty())
    {
        while (running())
        {
            auto const wait = remaining_slice();
            if (wait.count() <= 0)
            {
                break;
            }
            if (notifier.wait_for_change(since_stream_ordering, since_sync_stream_id, wait))
            {
                if (run())
                {
                    break;
                }
            }
            else if (!idle())
            {
                outcome.client_gone = true;
                break;
            }
        }
        return outcome;
    }
    // (a) The cursor first, then (b) the positions, then the rerun's own snapshot: each later than the one before.
    auto cursor = notifier.observe(user);
    if (notifier.wait_for_change(since_stream_ordering, since_sync_stream_id, std::chrono::milliseconds{0}) && run())
    {
        return outcome;
    }
    // (c)
    while (running())
    {
        auto const wait = remaining_slice();
        if (wait.count() <= 0)
        {
            break;
        }
        if (notifier.wait_for_change(cursor, wait))
        {
            // The new cursor before the rerun: a publish after it is seen by the next wait.
            cursor = notifier.observe(user);
            if (run())
            {
                break;
            }
        }
        else if (!idle())
        {
            outcome.client_gone = true;
            break;
        }
    }
    return outcome;
}

auto SyncNotifier::moved_since(WaitCursor const& cursor) -> bool
{
    auto lock = std::lock_guard{mutex_};
    auto const entry = by_user_.find(cursor.user);
    auto const user_generation = entry == by_user_.end() ? std::uint64_t{0U} : entry->second.generation;
    return user_generation != cursor.user_generation || broadcast_generation_ != cursor.broadcast_generation;
}

auto SyncNotifier::park(WaitCursor const& cursor, std::chrono::steady_clock::time_point deadline,
                        std::unique_ptr<ParkedPoll>& poll) -> ParkOutcome
{
    // Insert first, compare second: a publish before the insert moved a generation before the comparison.
    auto ticket = parked_.park(cursor.user, deadline, poll);
    if (ticket.parked && moved_since(cursor))
    {
        parked_.wake(ticket.ticket);
    }
    return ticket;
}

auto SyncNotifier::current_sync_stream_id() const -> std::uint64_t
{
    auto lock = std::lock_guard{mutex_};
    return sync_stream_id_;
}

auto SyncNotifier::waiting() const -> std::size_t
{
    auto lock = std::lock_guard{mutex_};
    return waiting_;
}

auto SyncNotifier::signals_sent() const -> std::uint64_t
{
    auto lock = std::lock_guard{mutex_};
    return signals_sent_;
}

} // namespace merovingian::sync