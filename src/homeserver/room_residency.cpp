// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/room_residency.hpp"

#include "merovingian/auth/identity.hpp"
#include "merovingian/homeserver/stored_room_version.hpp"

#include <algorithm>

namespace merovingian::homeserver
{

auto room_state_is_current(database::PersistentStore const& store, std::string_view room_id,
                           std::string_view local_server) -> bool
{
    if (!stored_room_version(store, room_id).has_value())
    {
        return false;
    }
    return std::ranges::any_of(store.memberships, [&](database::PersistentMembership const& membership) {
        return membership.room_id == room_id && membership.membership == "join" &&
               auth::user_id_server_name(membership.user_id) == local_server;
    });
}

} // namespace merovingian::homeserver
