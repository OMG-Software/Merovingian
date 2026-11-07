// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::platform
{

enum class HardeningStatus : std::uint8_t
{
    enabled,
    disabled,
    unknown,
};

} // namespace merovingian::platform
