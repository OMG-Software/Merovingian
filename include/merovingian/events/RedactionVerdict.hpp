// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::events
{

enum class RedactionVerdict
{
    // Spec, "Handling redactions": one of the two conditions holds.
    applies,
    // Neither condition holds; the redaction is kept but not applied.
    sender_lacks_authority,
    // The target is an event the server must keep whole (the room's m.room.create event).
    target_not_redactable,
};

} // namespace merovingian::events
