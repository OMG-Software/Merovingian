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

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields) -> void
    {
        LOG_DEBUG(observability::diagnostic_log_summary("sync_notifier", event, std::move(fields)));
    }

} // namespace

auto SyncNotifier::publish(std::uint64_t new_stream_id) -> void
{
    {
        auto lock = std::lock_guard{mutex_};
        if (new_stream_id <= stream_id_)
        {
            return;
        }
        stream_id_ = new_stream_id;
    }
    cv_.notify_all();
    log_diagnostic("stream.published", {{"stream_id", std::to_string(new_stream_id), false}});
}

auto SyncNotifier::wait_for_change(std::uint64_t since, std::chrono::milliseconds timeout) -> bool
{
    auto lock = std::unique_lock{mutex_};
    if (stream_id_ > since)
    {
        log_diagnostic("stream.changed_immediate", {{"since",     std::to_string(since),     false},
                                                    {"stream_id", std::to_string(stream_id_), false}});
        return true;
    }
    if (timeout.count() <= 0)
    {
        return false;
    }
    auto const changed = cv_.wait_for(lock, timeout, [this, since] { return stream_id_ > since; });
    log_diagnostic(changed ? "stream.changed" : "stream.timeout",
                   {{"since",     std::to_string(since),                                  false},
                    {"stream_id", std::to_string(stream_id_),                              false},
                    {"timeout_ms", std::to_string(timeout.count()),                        false}});
    return changed;
}

auto SyncNotifier::current_stream_id() const -> std::uint64_t
{
    auto lock = std::lock_guard{mutex_};
    return stream_id_;
}

} // namespace merovingian::sync
