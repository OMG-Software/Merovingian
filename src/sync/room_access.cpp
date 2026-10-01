// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/sync/room_access.hpp"

#include <cstdint>
#include <string_view>

namespace merovingian::sync
{

auto room_access_for(database::PersistentStore const& store, std::string_view room_id,
                     std::string_view user) noexcept -> RoomAccess
{
    auto found = false;
    auto newest_ordering = std::uint64_t{0U};
    auto newest_membership = std::string_view{};
    for (auto const& membership : store.memberships)
    {
        if (membership.room_id != room_id || membership.user_id != user)
        {
            continue;
        }
        if (!found || membership.stream_ordering >= newest_ordering)
        {
            found = true;
            newest_ordering = membership.stream_ordering;
            newest_membership = membership.membership;
        }
    }
    if (newest_membership == "join")
    {
        return RoomAccess::joined;
    }
    if (newest_membership == "invite")
    {
        return RoomAccess::invited;
    }
    return RoomAccess::none;
}

} // namespace merovingian::sync
