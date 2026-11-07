// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation/RemoteDeviceList.hpp"

#include <cstddef>
#include <string>

namespace merovingian::federation
{

auto RemoteDeviceList::bytes() const noexcept -> std::size_t
{
    auto total = master_key_json.value_or(std::string{}).size() + self_signing_key_json.value_or(std::string{}).size();
    for (auto const& [device_id, device] : devices)
    {
        total += device_id.size() + device.keys_json.size() + device.display_name.value_or(std::string{}).size();
    }
    return total;
}

} // namespace merovingian::federation
