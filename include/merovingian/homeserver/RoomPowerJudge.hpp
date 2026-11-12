// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/rooms/RoomVersionPolicy.hpp"

#include <string_view>

namespace merovingian::homeserver
{

// A room's power, judged by its current state as the authorization rules judge it: the create and power-levels events
// are read once, when the judge is made, and every question after that asks them. Holds no reference to the store, so
// it stays right only while the room's current state does not change; make one per decision.
class RoomPowerJudge final
{
public:
    RoomPowerJudge(database::PersistentStore const& store, std::string_view room_id);

    // Whether the room's create event is in current state and names a room version this server implements.
    [[nodiscard]] auto known() const noexcept -> bool;
    // Whether `user_id` may send a state event of `event_type`: their effective power level (room creators count as
    // infinite from room version 12) against events::required_state_event_power. False for an unknown room.
    [[nodiscard]] auto may_send_state_event(std::string_view user_id, std::string_view event_type) const -> bool;
    // Whether `user_id` may change the room's power levels or ban: a moderator, exempt from the joint cap on the tips
    // of senders without power (ADR-0695). False for an unknown room.
    [[nodiscard]] auto holds_room_power(std::string_view user_id) const -> bool;

private:
    canonicaljson::Value create_event_{};
    canonicaljson::Value power_levels_{};
    rooms::RoomVersionPolicy const* policy_{nullptr};
};

} // namespace merovingian::homeserver
