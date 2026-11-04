// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/sync/sync_notifier.hpp"

#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"

#include <chrono>
#include <cstddef>
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
        if (changed)
        {
            // The generations move and the waiters are signalled in the hold that moved the counters, so
            // a waiter either saw them at entry or is signalled here (ADR-0437).
            if (waiting_anyone_ > 0U)
            {
                ++signals_sent_;
                anyone_.notify_all();
            }
            if (!scope.has_value())
            {
                ++broadcast_generation_;
                for (auto& entry : by_user_)
                {
                    ++signals_sent_;
                    entry.second.wake.notify_all();
                }
            }
            else
            {
                for (auto const& user : *scope)
                {
                    auto const waiters = by_user_.find(user);
                    if (waiters == by_user_.end())
                    {
                        continue;
                    }
                    ++waiters->second.generation;
                    ++signals_sent_;
                    waiters->second.wake.notify_all();
                }
            }
        }
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
                                   std::chrono::milliseconds timeout, std::string_view user) -> bool
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
    auto changed = false;
    if (user.empty())
    {
        ++waiting_anyone_;
        changed = anyone_.wait_for(lock, timeout, [this, since_stream_ordering, since_sync_stream_id] {
            return stream_ordering_ > since_stream_ordering || sync_stream_id_ > since_sync_stream_id;
        });
        --waiting_anyone_;
    }
    else
    {
        auto entry = by_user_.find(user);
        if (entry == by_user_.end())
        {
            entry = by_user_.try_emplace(std::string{user}).first;
        }
        auto& waiters = entry->second;
        ++waiters.waiters;
        auto const generation = waiters.generation;
        auto const broadcast = broadcast_generation_;
        changed = waiters.wake.wait_for(lock, timeout, [this, &waiters, generation, broadcast] {
            return waiters.generation != generation || broadcast_generation_ != broadcast;
        });
        if (--waiters.waiters == 0U)
        {
            by_user_.erase(entry);
        }
    }
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