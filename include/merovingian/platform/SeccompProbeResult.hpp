// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>

namespace merovingian::platform
{

struct SeccompProbeResult final
{
    bool probed{false};               // true when at least one task's status was read successfully
    bool seccomp_active{false};       // true when EVERY task reports Seccomp: 2 and NoNewPrivs: 1
    std::size_t tasks_checked{0U};    // tasks whose status was read
    std::size_t unconfined_tasks{0U}; // tasks that were not confined, or whose status was unreadable
};

} // namespace merovingian::platform
