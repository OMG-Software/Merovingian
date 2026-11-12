// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/PersistentAuditEvent.hpp"

#include <cstddef>
#include <cstdint>
#include <deque>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>

namespace merovingian::homeserver
{

// The most distinct reports one reporter may file in `safety_report_budget_window_ms` (C26, ADR-0686).
inline constexpr auto max_safety_reports_per_reporter = std::size_t{100U};
inline constexpr auto safety_report_budget_window_ms = std::uint64_t{86'400'000U};

// What the trust-and-safety reporting routes remember so a report costs a hash lookup and not a read of `audit_log`
// (C26, ADR-0686). Each accepted report is a durable audit row; this index holds the (event type, reporter, target)
// of the newest `capacity` of them, which is the window the administrators' listing shows, so a repeat inside the
// window is acknowledged without a second row. It also holds the times of each reporter's recent reports, so one
// reporter's share of that window is bounded.
//
// It is filled once at start-up from the rows `audit_log` already holds (`rebuild`) and then by `admit`. Not
// thread-safe: the runtime mutex serialises every use.
class SafetyReportIndex final
{
public:
    enum class Admission : std::uint8_t
    {
        // Already reported inside the window: acknowledge, write nothing.
        duplicate,
        // New: the caller writes the audit row. The report is now remembered.
        admitted,
        // The reporter has filed `max_safety_reports_per_reporter` distinct reports in the budget window.
        reporter_over_budget,
    };

    // Judges a report and, when it is `admitted`, remembers it. `capacity` is the number of reports remembered.
    [[nodiscard]] auto admit(std::string_view event_type, std::string_view reporter, std::string_view target,
                             std::uint64_t now_ms, std::size_t capacity) -> Admission;

    // Replaces the contents with the report rows among `newest_first` (rows of any other event type are ignored).
    auto rebuild(std::span<database::PersistentAuditEvent const> newest_first, std::string_view report_action_suffix,
                 std::size_t capacity) -> void;

    // Reports remembered, and a reporter's reports inside the budget window. For tests.
    [[nodiscard]] auto size() const noexcept -> std::size_t;
    [[nodiscard]] auto reporter_reports(std::string_view reporter) const -> std::size_t;

private:
    auto remember(std::string key, std::size_t capacity) -> void;

    std::unordered_set<std::string> keys_{};
    // Oldest first.
    std::deque<std::string> order_{};
    // Each reporter's report times, oldest first.
    std::unordered_map<std::string, std::deque<std::uint64_t>> reporter_times_{};
};

} // namespace merovingian::homeserver
