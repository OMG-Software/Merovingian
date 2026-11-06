// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::homeserver
{

struct SyncAdmissionCaps final
{
    std::uint32_t global{0U};
    std::uint32_t per_user{0U};
    std::uint32_t per_device{0U};
};

} // namespace merovingian::homeserver
