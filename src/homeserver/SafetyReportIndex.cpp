// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/SafetyReportIndex.hpp"

#include <cstddef>
#include <cstdint>
#include <deque>
#include <span>
#include <string>
#include <string_view>
#include <utility>

namespace merovingian::homeserver
{

namespace
{

    // No part of a key holds a NUL byte: event types are fixed, user IDs and event IDs are Matrix identifiers.
    [[nodiscard]] auto report_key(std::string_view event_type, std::string_view reporter, std::string_view target)
        -> std::string
    {
        auto key = std::string{event_type};
        key.push_back('\0');
        key.append(reporter);
        key.push_back('\0');
        key.append(target);
        return key;
    }

    auto drop_times_outside_window(std::deque<std::uint64_t>& times, std::uint64_t now_ms) -> void
    {
        while (!times.empty() && now_ms > times.front() && now_ms - times.front() >= safety_report_budget_window_ms)
        {
            times.pop_front();
        }
    }

} // namespace

auto SafetyReportIndex::remember(std::string key, std::size_t capacity) -> void
{
    if (!keys_.insert(key).second)
    {
        return;
    }
    order_.push_back(std::move(key));
    while (order_.size() > capacity && !order_.empty())
    {
        keys_.erase(order_.front());
        order_.pop_front();
    }
}

auto SafetyReportIndex::admit(std::string_view event_type, std::string_view reporter, std::string_view target,
                              std::uint64_t now_ms, std::size_t capacity) -> Admission
{
    auto key = report_key(event_type, reporter, target);
    if (keys_.contains(key))
    {
        return Admission::duplicate;
    }
    auto const times = reporter_times_.find(std::string{reporter});
    if (times != reporter_times_.end())
    {
        drop_times_outside_window(times->second, now_ms);
        if (times->second.size() >= max_safety_reports_per_reporter)
        {
            return Admission::reporter_over_budget;
        }
    }
    reporter_times_[std::string{reporter}].push_back(now_ms);
    remember(std::move(key), capacity);
    return Admission::admitted;
}

auto SafetyReportIndex::rebuild(std::span<database::PersistentAuditEvent const> newest_first,
                                std::string_view report_action_suffix, std::size_t capacity) -> void
{
    keys_.clear();
    order_.clear();
    reporter_times_.clear();
    // Oldest first, so the newest rows are the ones kept when there are more than `capacity`.
    for (auto row = newest_first.rbegin(); row != newest_first.rend(); ++row)
    {
        if (!std::string_view{row->event_type}.ends_with(report_action_suffix))
        {
            continue;
        }
        remember(report_key(row->event_type, row->actor, row->target), capacity);
        if (row->created_at_ms != 0U)
        {
            reporter_times_[row->actor].push_back(row->created_at_ms);
        }
    }
}

auto SafetyReportIndex::size() const noexcept -> std::size_t
{
    return order_.size();
}

auto SafetyReportIndex::reporter_reports(std::string_view reporter) const -> std::size_t
{
    auto const times = reporter_times_.find(std::string{reporter});
    return times == reporter_times_.end() ? 0U : times->second.size();
}

} // namespace merovingian::homeserver
