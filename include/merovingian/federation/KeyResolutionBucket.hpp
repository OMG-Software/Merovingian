// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <chrono>
#include <cstdint>
#include <string>

namespace merovingian::federation
{

// Per-source-IP window for pre-authentication remote-key resolution.
struct KeyResolutionBucket final
{
    std::string source{};
    std::uint32_t resolutions_seen{0U};
    std::chrono::steady_clock::time_point window_start{};
};

} // namespace merovingian::federation
