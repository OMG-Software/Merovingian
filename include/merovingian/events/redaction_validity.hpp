// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <optional>
#include <string>

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

enum class RedactionVerdict
{
    // Spec, "Handling redactions": one of the two conditions holds.
    applies,
    // Neither condition holds; the redaction is kept but not applied.
    sender_lacks_authority,
    // The target is an event the server must keep whole (the room's m.room.create event).
    target_not_redactable,
};

// The event ID a redaction names. Spec (rooms/v11.md): `redacts` moved from the top level of the
// event to its `content` in room version 11, so the location follows the room version's redaction
// rules. nullopt for an event that is not an m.room.redaction, or has no string `redacts` there.
[[nodiscard]] auto redaction_target(canonicaljson::Value const& redaction_event, rooms::RoomVersionPolicy const& policy)
    -> std::optional<std::string>;

// Condition 1 of "Handling redactions" on its own: the redaction event's sender has a power level
// at least the room's redact level (default 50). This is also the level the Client-Server API
// requires to redact another user's event.
[[nodiscard]] auto sender_meets_redact_level(canonicaljson::Value const& redaction_event,
                                             RedactionContext const& context, rooms::RoomVersionPolicy const& policy)
    -> bool;

// Spec, "Handling redactions" (rooms/v3.md to rooms/v12.md): the server applies a redaction if
//   1. the redaction event's sender has a power level at least the redact level, or
//   2. the redaction event's sender's domain matches the original event's sender's domain.
// The redact level defaults to 50. A redaction of the room's m.room.create event is never applied:
// before room v11 the algorithm would strip `room_version` from it, and the server reads the room
// version from that event.
[[nodiscard]] auto judge_redaction(canonicaljson::Value const& redaction_event,
                                   canonicaljson::Value const& target_event, RedactionContext const& context,
                                   rooms::RoomVersionPolicy const& policy) -> RedactionVerdict;

} // namespace merovingian::events
