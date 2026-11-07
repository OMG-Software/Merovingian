// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::config
{

struct SizeLimitParseResult final
{
    bool valid{false};
    std::uint64_t bytes{0U};
};

} // namespace merovingian::config
