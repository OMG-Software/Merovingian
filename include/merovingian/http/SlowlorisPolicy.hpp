// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::http
{

struct SlowlorisPolicy final
{
    std::uint32_t min_bytes_per_second{64U};
    std::uint32_t grace_seconds{5U};
    std::uint32_t header_deadline_seconds{30U};
};

} // namespace merovingian::http
