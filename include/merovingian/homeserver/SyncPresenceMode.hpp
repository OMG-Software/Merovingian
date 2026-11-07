// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/PersistentStore.hpp"

#include <cstdint>

namespace merovingian::homeserver
{

// What the `set_presence` parameter of /sync asks for.
enum class SyncPresenceMode : std::uint8_t
{
    online,      // omitted or "online"
    unavailable, // "unavailable": "the client is marked as being idle"
    offline,     // "offline": "not marked as being online when it uses this API"
};

} // namespace merovingian::homeserver
