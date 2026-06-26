// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/sync/sync_notifier.hpp"

#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"

#include <chrono>
#include <mutex>
#include <string>
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

auto SyncNotifier::publish(std::uint64_t new_stream_ordering, std::uint64_t new_sync_stream_id) -> void
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
    }
    if (changed)
    {
        cv_.notify_all();
        log_diagnostic("stream.published",
                       {{"stream_ordering", std::to_string(new_stream_ordering),  false},
                        {"sync_stream_id",  std::to_string(new_sync_stream_id), false}});
    }
}

auto SyncNotifier::wait_for_change(std::uint64_t since_stream_ordering,
                                    std::uint64_t since_sync_stream_id,
                                    std::chrono::milliseconds timeout) -> bool
{
    auto lock = std::unique_lock{mutex_};
    if (stream_ordering_ > since_stream_ordering || sync_stream_id_ > since_sync_stream_id)
    {
        log_diagnostic("stream.changed_immediate",
                       {{"since_stream_ordering", std::to_string(since_stream_ordering), false},
                        {"since_sync_stream_id",  std::to_string(since_sync_stream_id),  false},
                        {"stream_ordering",       std::to_string(stream_ordering_),       false},
                        {"sync_stream_id",        std::to_string(sync_stream_id_),        false}});
        return true;
    }
    if (timeout.count() <= 0)
    {
        return false;
    }
    auto const changed = cv_.wait_for(
        lock, timeout,
        [this, since_stream_ordering, since_sync_stream_id] {
            return stream_ordering_ > since_stream_ordering || sync_stream_id_ > since_sync_stream_id;
        });
    log_diagnostic(changed ? "stream.changed" : "stream.timeout",
                   {{"since_stream_ordering", std::to_string(since_stream_ordering),                          false},
                    {"since_sync_stream_id",  std::to_string(since_sync_stream_id),                           false},
                    {"stream_ordering",       std::to_string(stream_ordering_),                                false},
                    {"sync_stream_id",        std::to_string(sync_stream_id_),                                 false},
                    {"timeout_ms",            std::to_string(timeout.count()),                                  false}});
    return changed;
}

auto SyncNotifier::current_sync_stream_id() const -> std::uint64_t
{
    auto lock = std::lock_guard{mutex_};
    return sync_stream_id_;
}

} // namespace merovingian::sync