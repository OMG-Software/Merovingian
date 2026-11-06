// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/platform/HardeningAction.hpp"
#include "merovingian/platform/HardeningMode.hpp"

#include <string>

namespace merovingian::platform
{

struct HardeningGate final
{
    std::string name{};
    HardeningAction action{HardeningAction::sandbox_profile};
    HardeningMode mode{HardeningMode::required};
    bool available{false};
};

} // namespace merovingian::platform
