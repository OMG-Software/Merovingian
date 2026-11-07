// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/Value.hpp"

namespace merovingian::events
{

// What a redaction needs, besides the two events, to be judged: the room's power levels as the
// redaction event itself saw them (the m.room.power_levels event among its auth_events) and the
// room's m.room.create event. A default-constructed (null) Value stands for "no such event".
struct RedactionContext final
{
    canonicaljson::Value power_levels{};
    canonicaljson::Value create{};
};

} // namespace merovingian::events
