// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation/DeviceDisplayNames.hpp"

#include "merovingian/database/PersistentStore.hpp"

#include <set>
#include <utility>

namespace merovingian::federation
{

DeviceDisplayNames::DeviceDisplayNames(database::PersistentStore const& store, std::span<std::string_view const> users)
{
    if (users.empty())
    {
        return;
    }
    auto const wanted = std::set<std::string_view>{users.begin(), users.end()};
    store.device_table_rows_examined.add(store.devices.size());
    for (auto const& device : store.devices)
    {
        if (wanted.contains(device.user_id))
        {
            names_.emplace(std::pair<std::string_view, std::string_view>{device.user_id, device.device_id},
                           std::string_view{device.display_name});
        }
    }
}

auto DeviceDisplayNames::find(std::string_view user_id, std::string_view device_id) const
    -> std::optional<std::string_view>
{
    auto const found = names_.find(std::pair<std::string_view, std::string_view>{user_id, device_id});
    return found == names_.end() ? std::nullopt : std::optional<std::string_view>{found->second};
}

} // namespace merovingian::federation
