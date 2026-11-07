// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/platform/HardeningStatus.hpp"

#include <string>

namespace merovingian::platform
{

struct HardeningCheck final
{
    std::string name{};
    HardeningStatus status{HardeningStatus::unknown};
    std::string note{};
};

} // namespace merovingian::platform
