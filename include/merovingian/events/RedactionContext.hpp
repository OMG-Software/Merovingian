// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/Value.hpp"

namespace merovingian::events
{

// What a redaction needs, besides the two events, to be judged: the room's power levels at one point
// of its state, and the room's m.room.create event. The caller reads both from the state this server
// holds, never from the event's own auth_events, which its sender chose (ADR-0586). A
// default-constructed (null) Value stands for "no such event".
struct RedactionContext final
{
    canonicaljson::Value power_levels{};
    canonicaljson::Value create{};
    // False when the state could not be read, as opposed to holding no power levels: the room's defaults
    // must not stand in for state this server does not have, so no sender meets the redact level.
    bool power_levels_known{true};
};

} // namespace merovingian::events
