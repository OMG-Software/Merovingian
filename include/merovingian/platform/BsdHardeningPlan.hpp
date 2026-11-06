// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::platform
{

struct BsdHardeningPlan final
{
    bool pledge_documented{true};
    bool unveil_documented{true};
    bool capsicum_documented{true};
    bool jail_documented{true};
    bool chroot_documented{true};
    bool setrlimit_documented{true};
};

} // namespace merovingian::platform
