// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <chrono>
#include <cstdint>
#include <string>

namespace merovingian::federation
{

// Per-source-IP window of failed X-Matrix signature checks (FED-4, ADR-0081).
struct BadSignatureBucket final
{
    std::string source{};
    std::uint32_t failures_seen{0U};
    std::chrono::steady_clock::time_point window_start{};
};

} // namespace merovingian::federation
