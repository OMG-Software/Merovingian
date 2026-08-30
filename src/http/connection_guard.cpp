// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/http/connection_guard.hpp"

#include <string>

namespace merovingian::http
{

auto slowloris_policy_is_valid(SlowlorisPolicy const& policy) noexcept -> bool
{
    return policy.min_bytes_per_second > 0U && policy.grace_seconds <= policy.header_deadline_seconds &&
           policy.header_deadline_seconds > 0U && policy.header_deadline_seconds <= 300U;
}

auto request_progress_is_too_slow(RequestProgress progress, SlowlorisPolicy policy) noexcept -> bool
{
    if (!slowloris_policy_is_valid(policy))
    {
        return true;
    }

    if (progress.elapsed_seconds <= policy.grace_seconds)
    {
        return false;
    }

    if (progress.elapsed_seconds > policy.header_deadline_seconds)
    {
        return true;
    }

    auto const measured_seconds = progress.elapsed_seconds - policy.grace_seconds;
    auto const required_bytes = static_cast<std::uint64_t>(measured_seconds) * policy.min_bytes_per_second;
    return progress.bytes_received < required_bytes;
}

auto slowloris_policy_summary(SlowlorisPolicy const& policy) -> std::string
{
    return "HTTP slowloris policy: min_bytes_per_second=" + std::to_string(policy.min_bytes_per_second) +
           " grace_seconds=" + std::to_string(policy.grace_seconds) +
           " header_deadline_seconds=" + std::to_string(policy.header_deadline_seconds);
}

auto connection_should_close(ConnectionPhase phase, RequestProgress progress, SlowlorisPolicy const& slowloris,
                             KeepAlivePolicy const& keep_alive) noexcept -> bool
{
    switch (phase)
    {
    case ConnectionPhase::awaiting_request:
        // Idle-after-complete-request: bounded ONLY by the keep-alive idle
        // window. The slowloris rate must not be applied here — a connection
        // with no request in flight receives no bytes by design, so any
        // bytes-per-second test would kill every keep-alive connection as
        // "slow" at the end of its grace period.
        if (!keep_alive_policy_is_valid(keep_alive))
        {
            return true;
        }
        return progress.elapsed_seconds > keep_alive.idle_timeout_seconds;
    case ConnectionPhase::reading_request:
        // Mid-request: the slowloris policy applies in full.
        return request_progress_is_too_slow(progress, slowloris);
    }
    return true;
}

} // namespace merovingian::http
