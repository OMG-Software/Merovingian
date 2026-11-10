// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/RemoteDeviceListScope.hpp"

#include "merovingian/auth/Identity.hpp"

#include <string>
#include <string_view>
#include <unordered_set>

namespace merovingian::homeserver
{

auto remote_users_sharing_a_room_with_local_users(database::PersistentStore const& store, std::string_view local_server,
                                                  std::unordered_set<std::string_view> const& candidates)
    -> std::unordered_set<std::string>
{
    auto sharing = std::unordered_set<std::string>{};
    if (candidates.empty())
    {
        return sharing;
    }
    auto rooms_with_local_members = std::unordered_set<std::string_view>{};
    for (auto const& membership : store.memberships)
    {
        if (membership.membership == "join" && auth::user_id_server_name(membership.user_id) == local_server)
        {
            rooms_with_local_members.insert(membership.room_id);
        }
    }
    for (auto const& membership : store.memberships)
    {
        if (membership.membership == "join" && candidates.contains(membership.user_id) &&
            rooms_with_local_members.contains(membership.room_id))
        {
            sharing.insert(membership.user_id);
        }
    }
    return sharing;
}

} // namespace merovingian::homeserver
