// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>
#include <vector>

namespace merovingian::federation
{

struct InviteRequest final
{
    std::string room_id{};
    std::string event_id{};
    std::string room_version{};
    std::string invite_event_json{};
    std::vector<std::string> invite_room_state_json{};
    // The X-Matrix-authenticated origin of the requesting server. The invite
    // handler asserts that the event sender's server name matches this origin
    // (spec §4223: "the event sender is not a user ID on the origin server").
    std::string origin{};
};

} // namespace merovingian::federation
