// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace merovingian::database
{

struct PersistentInvite final
{
    std::string room_id{};
    std::string user_id{};
    std::string sender_user_id{};
    std::string event_id{};
    std::string signed_event_json{};
    std::vector<std::string> invite_state_events_json{};
    std::uint64_t stream_ordering{0U};
    // A knock's record: the resident server that accepted the knock, where its
    // withdrawal goes (ADR-0251). Empty for an invite and for a knock on a room
    // this server is in.
    std::string resident_server{};
};

} // namespace merovingian::database
