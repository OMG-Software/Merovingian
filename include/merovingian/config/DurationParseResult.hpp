// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::config
{

struct DurationParseResult final
{
    bool valid{false};
    std::uint32_t seconds{0U};
};

} // namespace merovingian::config
