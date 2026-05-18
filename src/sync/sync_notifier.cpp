// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/sync/sync_notifier.hpp"

#include <chrono>
#include <mutex>

namespace merovingian::sync
{

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
}

auto SyncNotifier::wait_for_change(std::uint64_t since, std::chrono::milliseconds timeout) -> bool
{
    auto lock = std::unique_lock{mutex_};
    if (stream_id_ > since)
    {
        return true;
    }
    if (timeout.count() <= 0)
    {
        return false;
    }
    return cv_.wait_for(lock, timeout, [this, since] { return stream_id_ > since; });
}

auto SyncNotifier::current_stream_id() const -> std::uint64_t
{
    auto lock = std::lock_guard{mutex_};
    return stream_id_;
}

} // namespace merovingian::sync
