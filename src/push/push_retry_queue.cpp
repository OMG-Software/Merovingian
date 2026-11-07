// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/push/push_retry_queue.hpp"

#include "merovingian/push/push_gateway_client.hpp"

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
    if (result.busy)
    {
        // Held back by the in-flight cap on its gateway (F-79): nothing was sent, so try again.
        return true;
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
    auto const due_count = static_cast<std::size_t>(std::distance(entries_.begin(), due_end));
    // Round robin by recipient (F-81, ADR-0410): one user's backlog of due retries cannot stand in
    // front of everyone else's. The users are ordered by their earliest due retry and each user's
    // retries by due time, so with one user due this is the plain earliest-first order.
    auto by_user = std::vector<std::pair<std::string_view, std::vector<std::size_t>>>{};
    for (auto index = std::size_t{0U}; index < due_count; ++index)
    {
        auto const user = std::string_view{entries_[index].user_id};
        auto const found = std::ranges::find_if(by_user, [user](auto const& entry) {
            return entry.first == user;
        });
        if (found == by_user.end())
        {
            by_user.emplace_back(user, std::vector<std::size_t>{index});
        }
        else
        {
            found->second.push_back(index);
        }
    }
    auto chosen = std::vector<std::size_t>{};
    chosen.reserve(std::min(due_count, max));
    for (auto round = std::size_t{0U}; chosen.size() < max && chosen.size() < due_count; ++round)
    {
        for (auto const& [user, indices] : by_user)
        {
            if (round < indices.size() && chosen.size() < max)
            {
                chosen.push_back(indices[round]);
            }
        }
    }
    auto taken = std::vector<PushRetry>{};
    taken.reserve(chosen.size());
    for (auto const index : chosen)
    {
        taken.push_back(std::move(entries_[index]));
    }
    // Moved-from rows are the ones named in `chosen`; erase them by position.
    std::ranges::sort(chosen);
    for (auto position = chosen.size(); position > 0U; --position)
    {
        entries_.erase(entries_.begin() + static_cast<std::ptrdiff_t>(chosen[position - 1U]));
    }
    return taken;
}

auto PushRetryQueue::return_untried(PushRetry retry) -> void
{
    auto const guard = std::lock_guard{mutex_};
    entries_.push_back(std::move(retry));
}

auto PushRetryQueue::drop_pusher(std::string_view user_id, std::string_view app_id, std::string_view pushkey)
    -> std::size_t
{
    auto const guard = std::lock_guard{mutex_};
    return static_cast<std::size_t>(std::erase_if(entries_, [user_id, app_id, pushkey](PushRetry const& queued) {
        return queued.user_id == user_id && queued.app_id == app_id && queued.pushkey == pushkey;
    }));
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
