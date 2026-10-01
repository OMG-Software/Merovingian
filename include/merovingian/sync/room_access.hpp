// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/persistent_store.hpp"

#include <string_view>

namespace merovingian::sync
{

// What a user may be shown about a room that a sliding sync request names.
enum class RoomAccess
{
    // No current entitlement: no membership, or leave, ban or knock. The room is omitted.
    none,
    // The user holds an invite. Only the invite's stripped state may be shown.
    invited,
    // The user is joined: the room may be served in full.
    joined,
};

// Classifies the user's CURRENT membership of `room_id` from the persistent store.
//
// Spec (client-server-api.md, "Room history visibility"): "In all cases except
// `world_readable`, a user needs to join a room to view events in that room." Sliding sync
// deliberately does not treat `world_readable` as permission here: only `join` grants the
// full room, `invite` grants the stripped invite state, and everything else grants nothing.
//
// When the store holds more than one membership row for the pair, the row with the highest
// stream ordering is the current one. An unknown room or user yields `RoomAccess::none`
// (fail closed).
[[nodiscard]] auto room_access_for(database::PersistentStore const& store, std::string_view room_id,
                                   std::string_view user) noexcept -> RoomAccess;

} // namespace merovingian::sync
