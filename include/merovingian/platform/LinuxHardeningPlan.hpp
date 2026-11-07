// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::platform
{

struct LinuxHardeningPlan final
{
    bool seccomp_filter_required{true};
    bool no_new_privs_required{true};
    bool capability_bounding_required{true};
    bool core_dump_policy_required{true};
    bool landlock_documented{true};
    bool apparmor_documented{true};
    bool selinux_documented{true};
    bool systemd_sandboxing_documented{true};
};

} // namespace merovingian::platform
