// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>

namespace merovingian::sync
{

// The bounds of a ParkedPollRegistry. A park past either is refused.
struct ParkedPollLimits final
{
    std::size_t max_parked{1024U};
    std::size_t max_parked_per_user{4U};
};

} // namespace merovingian::sync
