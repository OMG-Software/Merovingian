// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/PresenceWriteStatus.hpp"

#include <cstdint>

namespace merovingian::homeserver
{

struct PresenceWrite final
{
    PresenceWriteStatus status{PresenceWriteStatus::failed};
    // When `status` is limited: how long until a change is kept, at least 1 ms.
    std::uint32_t retry_after_ms{0U};
};

} // namespace merovingian::homeserver
