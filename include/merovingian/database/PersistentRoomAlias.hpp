// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::database
{

struct PersistentRoomAlias final
{
    std::string room_alias{};
    std::string room_id{};
    // The local user who created the alias, who may always delete it (CSAZ-12).
    // Empty for an alias created before schema version 21, or by createRoom's
    // `room_alias_name` before then.
    std::string creator_user_id{};
};

} // namespace merovingian::database
