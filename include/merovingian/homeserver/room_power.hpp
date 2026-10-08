// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/persistent_store.hpp"

#include <string_view>

namespace merovingian::homeserver
{

// CSAZ-12: whether `user_id` may send a state event of `event_type` in `room_id`,
// judged by the room's current state exactly as the authorization rules would
// judge it: the user's effective power level (room creators count as infinite
// from room version 12) against events::required_state_event_power.
//
// Client API gates use it to refuse an action before doing anything, when the
// state event the action stands for would be rejected: a room upgrade needs
// m.room.tombstone, and directory visibility and alias changes need
// m.room.canonical_alias. False when the room's create event is not in this
// server's state, or its room version is unknown.
[[nodiscard]] auto may_send_state_event(database::PersistentStore const& store, std::string_view room_id,
                                        std::string_view user_id, std::string_view event_type) -> bool;

} // namespace merovingian::homeserver
