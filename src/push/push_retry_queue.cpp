// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/push/push_retry_queue.hpp"

#include <algorithm>
#include <iterator>
#include <utility>

namespace merovingian::push
{

auto push_retry_backoff(std::uint32_t failed_attempts) noexcept -> std::chrono::milliseconds
{
    auto backoff = std::chrono::milliseconds{push_retry_initial_backoff};
    for (auto attempt = std::uint32_t{1U}; attempt < failed_attempts && backoff < push_retry_max_backoff; ++attempt)
    {
        backoff *= 2;
    }
    return std::min(backoff, std::chrono::milliseconds{push_retry_max_backoff});
}

auto push_delivery_should_retry(PushGatewayResult const& result) noexcept -> bool
{
    if (result.disabled)
    {
        return false;
    }
    if (result.ok)
    {
        return result.status < 200U || result.status >= 300U;
    }
    return gateway_circuit_outcome(result) == GatewayCircuitOutcome::transport_failure;
}

auto PushRetryQueue::schedule(PushRetry retry, std::chrono::steady_clock::time_point now) -> PushRetryAdmission
{
    if (retry.failed_attempts > push_retry_max_retries)
    {
        return PushRetryAdmission::gave_up;
    }
    auto const guard = std::lock_guard{mutex_};
    auto const for_user = std::ranges::count_if(entries_, [&retry](PushRetry const& queued) {
        return queued.user_id == retry.user_id;
    });
    if (entries_.size() >= push_retry_queue_capacity ||
        static_cast<std::size_t>(for_user) >= push_retry_per_user_capacity)
    {
        return PushRetryAdmission::queue_full;
    }
    retry.due = now + push_retry_backoff(retry.failed_attempts);
    entries_.push_back(std::move(retry));
    if (wake_)
    {
        wake_();
    }
    return PushRetryAdmission::queued;
}

auto PushRetryQueue::take_due(std::chrono::steady_clock::time_point now, std::size_t max) -> std::vector<PushRetry>
{
    auto const guard = std::lock_guard{mutex_};
    std::ranges::stable_sort(entries_, {}, &PushRetry::due);
    auto const due_end = std::ranges::find_if(entries_, [now](PushRetry const& queued) {
        return queued.due > now;
    });
    auto const count = std::min(static_cast<std::size_t>(std::distance(entries_.begin(), due_end)), max);
    auto taken = std::vector<PushRetry>{};
    taken.reserve(count);
    std::ranges::move(entries_.begin(), entries_.begin() + static_cast<std::ptrdiff_t>(count),
                      std::back_inserter(taken));
    entries_.erase(entries_.begin(), entries_.begin() + static_cast<std::ptrdiff_t>(count));
    return taken;
}

auto PushRetryQueue::drop_pushkey(std::string_view app_id, std::string_view pushkey) -> std::size_t
{
    auto const guard = std::lock_guard{mutex_};
    return static_cast<std::size_t>(std::erase_if(entries_, [app_id, pushkey](PushRetry const& queued) {
        return queued.app_id == app_id && queued.pushkey == pushkey;
    }));
}

auto PushRetryQueue::next_due() const -> std::optional<std::chrono::steady_clock::time_point>
{
    auto const guard = std::lock_guard{mutex_};
    auto const earliest = std::ranges::min_element(entries_, {}, &PushRetry::due);
    return earliest == entries_.end() ? std::nullopt : std::optional{earliest->due};
}

auto PushRetryQueue::size() const -> std::size_t
{
    auto const guard = std::lock_guard{mutex_};
    return entries_.size();
}

auto PushRetryQueue::set_wake(std::function<void()> wake) -> void
{
    auto const guard = std::lock_guard{mutex_};
    wake_ = std::move(wake);
}

} // namespace merovingian::push
