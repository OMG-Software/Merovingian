// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::platform
{

struct MemoryLockingPlan final
{
    bool lock_secret_pages{true};
    bool disable_core_dumps{true};
    bool wipe_on_release{true};
};

} // namespace merovingian::platform
