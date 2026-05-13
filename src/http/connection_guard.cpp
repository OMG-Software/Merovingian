// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/http/connection_guard.hpp"

#include <string>

namespace merovingian::http
{

auto slowloris_policy_is_valid(SlowlorisPolicy const& policy) noexcept -> bool
{
    return policy.min_bytes_per_second > 0U && policy.grace_seconds <= policy.header_deadline_seconds
        && policy.header_deadline_seconds > 0U && policy.header_deadline_seconds <= 300U;
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
    return "HTTP slowloris policy: min_bytes_per_second=" + std::to_string(policy.min_bytes_per_second)
        + " grace_seconds=" + std::to_string(policy.grace_seconds)
        + " header_deadline_seconds=" + std::to_string(policy.header_deadline_seconds);
}

} // namespace merovingian::http
