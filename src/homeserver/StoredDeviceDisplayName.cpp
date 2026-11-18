// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/StoredDeviceDisplayName.hpp"

#include "merovingian/database/PersistentDevice.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"

#include <string>
#include <string_view>

namespace merovingian::homeserver
{

auto stored_device_display_name(HomeserverRuntime const& runtime, std::string_view user_id, std::string_view device_id)
    -> std::string
{
    auto name = std::string{};
    database::for_each_user_device(runtime.database.persistent_store, user_id,
                                   [&](database::PersistentDevice const& device) {
                                       if (device.device_id != device_id)
                                       {
                                           return true;
                                       }
                                       name = device.display_name;
                                       return false;
                                   });
    return name;
}

} // namespace merovingian::homeserver
