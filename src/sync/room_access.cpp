// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/sync/room_access.hpp"

#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <string_view>
#include <utility>

namespace merovingian::sync
{

namespace
{

    [[nodiscard]] auto access_from_membership(std::string_view membership) noexcept -> RoomAccess
    {
        if (membership == "join")
        {
            return RoomAccess::joined;
        }
        if (membership == "invite")
        {
            return RoomAccess::invited;
        }
        return RoomAccess::none;
    }

} // namespace

auto room_access_for(database::PersistentStore const& store, std::string_view room_id, std::string_view user) noexcept
    -> RoomAccess
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
    return access_from_membership(newest_membership);
}

auto room_access_index(database::PersistentStore const& store, std::string_view user)
    -> std::map<std::string, RoomAccess, std::less<>>
{
    // Newest row per room, with the same tie rule as room_access_for: on an equal stream
    // ordering the row stored later wins.
    auto newest = std::map<std::string_view, std::pair<std::uint64_t, std::string_view>, std::less<>>{};
    for (auto const& membership : store.memberships)
    {
        if (membership.user_id != user)
        {
            continue;
        }
        auto const [found, inserted] = newest.try_emplace(
            membership.room_id, std::pair{membership.stream_ordering, std::string_view{membership.membership}});
        if (!inserted && membership.stream_ordering >= found->second.first)
        {
            found->second = std::pair{membership.stream_ordering, std::string_view{membership.membership}};
        }
    }
    auto index = std::map<std::string, RoomAccess, std::less<>>{};
    for (auto const& [room_id, row] : newest)
    {
        index.emplace(std::string{room_id}, access_from_membership(row.second));
    }
    return index;
}

} // namespace merovingian::sync
