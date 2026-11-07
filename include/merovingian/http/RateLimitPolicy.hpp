// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::http
{

struct RateLimitPolicy final
{
    std::uint32_t max_requests{90U};
    std::uint32_t window_seconds{60U};

    [[nodiscard]] auto operator==(RateLimitPolicy const& other) const noexcept -> bool = default;
};

} // namespace merovingian::http
