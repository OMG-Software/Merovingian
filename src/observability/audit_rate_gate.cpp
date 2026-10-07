// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/observability/audit_rate_gate.hpp"

#include <utility>

namespace merovingian::observability
{

auto audit_event_is_rate_capped(std::string_view event_type) noexcept -> bool
{
    return event_type == "access_token.rejected" || event_type == "rate_limit.exceeded" ||
           event_type == "request.rejected" || event_type == "login.rejected" || event_type == "login.throttled";
}

auto AuditRateGate::admit(std::string_view event_type) -> AuditRateDecision
{
    return admit(event_type, clock_ ? clock_() : Clock::now());
}

auto AuditRateGate::admit(std::string_view event_type, Clock::time_point now) -> AuditRateDecision
{
    if (!audit_event_is_rate_capped(event_type))
    {
        return {};
    }
    auto found = windows_.find(event_type);
    if (found == windows_.end())
    {
        found = windows_.emplace(std::string{event_type}, Window{now, 0U, 0U}).first;
    }
    auto& window = found->second;

    auto carried = std::uint64_t{0U};
    if (now - window.started >= audit_rate_gate_window || now < window.started)
    {
        // A new window opens. What the previous one suppressed rides on the
        // first row this one writes. A clock that stepped backwards also opens
        // a window rather than freezing the kind's allowance.
        carried = window.suppressed;
        window = Window{now, 0U, 0U};
    }
    if (window.written < audit_rate_gate_max_rows)
    {
        ++window.written;
        return {true, carried};
    }
    // Over the allowance: count it. `carried` is zero here because a window that
    // has just opened always has allowance left.
    ++window.suppressed;
    return {false, 0U};
}

auto AuditRateGate::set_clock(NowFn clock) -> void
{
    clock_ = std::move(clock);
}

auto AuditRateGate::tracked_kinds() const noexcept -> std::size_t
{
    return windows_.size();
}

} // namespace merovingian::observability
