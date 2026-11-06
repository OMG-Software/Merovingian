// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::platform
{

struct ResourceLimitPlan final
{
    std::uint64_t max_open_files{1024U};
    std::uint64_t max_processes{64U};
    std::uint64_t max_address_space_bytes{0U};
    std::uint64_t max_core_bytes{0U};
};

} // namespace merovingian::platform
