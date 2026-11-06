// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::platform
{

enum class HardeningAction
{
    privilege_drop,
    filesystem_restriction,
    resource_limit,
    memory_locking,
    random_source,
    signal_handling,
    syscall_filter,
    capability_bounding,
    sandbox_profile,
};

} // namespace merovingian::platform
