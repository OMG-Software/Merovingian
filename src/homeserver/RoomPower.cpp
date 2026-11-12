// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/RoomPower.hpp"

#include "merovingian/homeserver/RoomPowerJudge.hpp"

namespace merovingian::homeserver
{

auto may_send_state_event(database::PersistentStore const& store, std::string_view room_id, std::string_view user_id,
                          std::string_view event_type) -> bool
{
    return RoomPowerJudge{store, room_id}.may_send_state_event(user_id, event_type);
}

} // namespace merovingian::homeserver
