// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/federation/RemoteCachedDevice.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace merovingian::federation
{

// One `m.device_list_update` EDU, checked and reduced to what the remote device-list cache applies (ADR-0561).
// `device` is the device's new entry, unused when `deleted`.
struct RemoteDeviceListUpdate final
{
    std::string user_id{};
    std::string device_id{};
    std::int64_t stream_id{0};
    std::vector<std::int64_t> prev_ids{};
    bool deleted{false};
    RemoteCachedDevice device{};
};

} // namespace merovingian::federation
