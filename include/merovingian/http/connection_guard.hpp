// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::http
{

struct SlowlorisPolicy final
{
    std::uint32_t min_bytes_per_second{64U};
    std::uint32_t grace_seconds{5U};
    std::uint32_t header_deadline_seconds{30U};
};

struct RequestProgress final
{
    std::uint64_t bytes_received{0U};
    std::uint32_t elapsed_seconds{0U};
};

[[nodiscard]] auto slowloris_policy_is_valid(SlowlorisPolicy const& policy) noexcept -> bool;
[[nodiscard]] auto request_progress_is_too_slow(RequestProgress progress, SlowlorisPolicy policy) noexcept -> bool;
[[nodiscard]] auto slowloris_policy_summary(SlowlorisPolicy const& policy) -> std::string;

} // namespace merovingian::http
