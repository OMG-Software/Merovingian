// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <chrono>
#include <cstdint>

namespace merovingian::federation
{

struct RemoteTrustState final
{
    std::uint32_t consecutive_failures{0U};
    // When the most recent failure was recorded. A default (epoch) value means
    // "unknown", which never decays: fail closed.
    std::chrono::steady_clock::time_point last_failure_at{};
    std::uint32_t reputation_score{100U};
    bool quarantined{false};
    bool circuit_open{false};
};

} // namespace merovingian::federation
