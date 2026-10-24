// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "merovingian/push/email_digest_queue.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <utility>
#include <vector>

namespace merovingian::push
{

auto email_digest_backoff(std::uint32_t failed_attempts) noexcept -> std::chrono::milliseconds
{
    auto backoff = std::chrono::milliseconds{email_digest_initial_backoff};
    auto const ceiling = std::chrono::milliseconds{email_digest_max_backoff};
    for (auto attempt = std::uint32_t{1U}; attempt < failed_attempts && backoff < ceiling; ++attempt)
    {
        backoff *= 2;
    }
    return std::min(backoff, ceiling);
}

auto EmailDigestQueue::schedule(Entry& entry, std::chrono::steady_clock::time_point now,
                                EmailDigestPolicy const& policy) -> void
{
    auto due = now + policy.delay;
    if (entry.last_sent.has_value())
    {
        due = std::max(due, *entry.last_sent + policy.throttle);
    }
    entry.due = due;
    entry.failed_attempts = 0U;
    if (wake_)
    {
        wake_();
    }
}

// Releases entries that hold nothing: not due, not being sent, and either never sent or sent longer
// ago than their throttle (so they no longer delay the next email).
auto EmailDigestQueue::release_idle(std::chrono::steady_clock::time_point now) -> void
{
    std::erase_if(entries_, [now](auto const& item) {
        auto const& entry = item.second;
        return !entry.due.has_value() && !entry.sending &&
               (!entry.last_sent.has_value() || now - *entry.last_sent >= entry.throttle);
    });
}

auto EmailDigestQueue::note_notification(EmailDigestKey const& key, std::chrono::steady_clock::time_point now,
                                         EmailDigestPolicy const& policy) -> EmailDigestAdmission
{
    auto const lock = std::lock_guard{mutex_};
    auto existing = entries_.find(key);
    if (existing != entries_.end())
    {
        auto& entry = existing->second;
        if (entry.sending)
        {
            entry.renotified = true;
            return EmailDigestAdmission::folded;
        }
        if (entry.due.has_value())
        {
            return EmailDigestAdmission::folded;
        }
        schedule(entry, now, policy);
        return EmailDigestAdmission::scheduled;
    }
    if (entries_.size() >= email_digest_queue_capacity)
    {
        release_idle(now);
        if (entries_.size() >= email_digest_queue_capacity)
        {
            return EmailDigestAdmission::queue_full;
        }
    }
    auto& entry = entries_[key];
    schedule(entry, now, policy);
    return EmailDigestAdmission::scheduled;
}

auto EmailDigestQueue::take_due(std::chrono::steady_clock::time_point now, std::size_t max)
    -> std::vector<EmailDigestKey>
{
    auto const lock = std::lock_guard{mutex_};
    auto due = std::vector<std::pair<std::chrono::steady_clock::time_point, EmailDigestKey const*>>{};
    for (auto const& [key, entry] : entries_)
    {
        if (entry.due.has_value() && *entry.due <= now)
        {
            due.emplace_back(*entry.due, &key);
        }
    }
    std::ranges::sort(due, [](auto const& left, auto const& right) {
        return left.first < right.first;
    });
    if (due.size() > max)
    {
        due.resize(max);
    }
    auto taken = std::vector<EmailDigestKey>{};
    taken.reserve(due.size());
    for (auto const& [when, key] : due)
    {
        auto& entry = entries_.at(*key);
        entry.due.reset();
        entry.sending = true;
        entry.renotified = false;
        taken.push_back(*key);
    }
    return taken;
}

auto EmailDigestQueue::complete(EmailDigestKey const& key, EmailDigestOutcome outcome,
                                std::chrono::steady_clock::time_point now, EmailDigestPolicy const& policy) -> bool
{
    auto const lock = std::lock_guard{mutex_};
    auto existing = entries_.find(key);
    if (existing == entries_.end())
    {
        return false;
    }
    auto& entry = existing->second;
    entry.sending = false;
    auto const renotified = std::exchange(entry.renotified, false);
    switch (outcome)
    {
    case EmailDigestOutcome::abandoned:
        entries_.erase(existing);
        return false;
    case EmailDigestOutcome::failed:
        ++entry.failed_attempts;
        if (entry.failed_attempts < email_digest_max_attempts)
        {
            entry.due = now + email_digest_backoff(entry.failed_attempts);
            if (wake_)
            {
                wake_();
            }
            return true;
        }
        entry.failed_attempts = 0U;
        break;
    case EmailDigestOutcome::sent:
        entry.last_sent = now;
        entry.throttle = policy.throttle;
        entry.failed_attempts = 0U;
        break;
    case EmailDigestOutcome::nothing_unread:
        entry.failed_attempts = 0U;
        break;
    }
    if (renotified)
    {
        schedule(entry, now, policy);
    }
    else if (!entry.last_sent.has_value() || now - *entry.last_sent >= entry.throttle)
    {
        entries_.erase(existing);
    }
    return false;
}

auto EmailDigestQueue::forget(EmailDigestKey const& key) -> void
{
    auto const lock = std::lock_guard{mutex_};
    entries_.erase(key);
}

auto EmailDigestQueue::next_due() const -> std::optional<std::chrono::steady_clock::time_point>
{
    auto const lock = std::lock_guard{mutex_};
    auto earliest = std::optional<std::chrono::steady_clock::time_point>{};
    for (auto const& [key, entry] : entries_)
    {
        if (entry.due.has_value() && (!earliest.has_value() || *entry.due < *earliest))
        {
            earliest = entry.due;
        }
    }
    return earliest;
}

auto EmailDigestQueue::size() const -> std::size_t
{
    auto const lock = std::lock_guard{mutex_};
    return entries_.size();
}

auto EmailDigestQueue::set_wake(std::function<void()> wake) -> void
{
    auto const lock = std::lock_guard{mutex_};
    wake_ = std::move(wake);
}

} // namespace merovingian::push
