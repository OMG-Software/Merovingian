// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::platform
{

// What one /proc/<pid>/task/<tid>/status says about a single task's seccomp
// confinement. Seccomp filters and no_new_privs are per-task attributes, so a
// process is only confined when every task is.
struct TaskConfinement final
{
    bool parsed{false};   // both fields were present and numeric
    int seccomp_mode{-1}; // 0 disabled, 1 strict, 2 filter
    int no_new_privs{-1}; // 0 or 1

    // Fail-closed: a task that could not be fully parsed is never confined.
    [[nodiscard]] constexpr auto confined() const noexcept -> bool
    {
        return parsed && seccomp_mode == 2 && no_new_privs == 1;
    }
};

} // namespace merovingian::platform
