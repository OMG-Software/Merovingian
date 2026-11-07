// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/RoomMembers.hpp"

#include <string>

namespace merovingian::homeserver
{

struct LocalRoom final
{
    std::string room_id{};
    std::string creator_user_id{};
    // The joined members; written only through RoomMembers' methods (ADR-0496).
    RoomMembers members{};
    // True when the room has been explicitly published to the public room directory
    // via PUT /_matrix/client/v3/directory/list/room/{roomId}. Private by default.
    bool directory_public{false};
};

} // namespace merovingian::homeserver
