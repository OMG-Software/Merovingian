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
    // When `status` is limited: how long until a change can be kept, at least 1 ms.
    std::uint32_t retry_after_ms{0U};
    // When `status` is limited: true when `AccountPresenceTracker` had no room for the account (ADR-0876), false when
    // the account's own window is open.
    bool tracker_full{false};
};

} // namespace merovingian::homeserver
