// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/sync/SlidingSyncOp.hpp"

#include <cstdint>
#include <vector>

namespace merovingian::sync
{

// MSC4186 §lists[*] response
struct SlidingSyncListResponse final
{
    std::uint64_t count{0U}; // total rooms matching the list's filters
    std::vector<SlidingSyncOp> ops{};
};

} // namespace merovingian::sync
