// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/platform/BsdHardeningPlan.hpp"
#include "merovingian/platform/FilesystemRestrictionPlan.hpp"
#include "merovingian/platform/HardeningMode.hpp"
#include "merovingian/platform/HardeningPlatform.hpp"
#include "merovingian/platform/LinuxHardeningPlan.hpp"
#include "merovingian/platform/MemoryLockingPlan.hpp"
#include "merovingian/platform/PrivilegeDropPlan.hpp"
#include "merovingian/platform/RandomSourcePlan.hpp"
#include "merovingian/platform/ResourceLimitPlan.hpp"
#include "merovingian/platform/SignalHandlingPlan.hpp"

namespace merovingian::platform
{

struct RuntimeHardeningProfile final
{
    HardeningPlatform platform{HardeningPlatform::portable};
    HardeningMode mode{HardeningMode::required};
    PrivilegeDropPlan privilege_drop{};
    FilesystemRestrictionPlan filesystem{};
    ResourceLimitPlan resources{};
    MemoryLockingPlan memory{};
    RandomSourcePlan random{};
    SignalHandlingPlan signals{};
    LinuxHardeningPlan linux{};
    BsdHardeningPlan bsd{};
};

} // namespace merovingian::platform
