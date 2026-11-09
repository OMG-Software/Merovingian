// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace merovingian::federation
{

// The `m.device_list_update` EDU contents announcing one local user's devices, built together
// (`build_device_list_update_batch`, security audit run-4 F-05, ADR-0582). The cost is counted in passes over the
// two device tables, not in time, so a test can show it does not grow with the number of devices.
struct DeviceListUpdateBatch final
{
    // One device's EDU content. `has_keys` is false when the device has published no keys: its content then
    // carries no `keys` member.
    struct Entry final
    {
        std::string device_id{};
        std::string content{};
        bool has_keys{false};
    };

    std::vector<Entry> entries{};
    // Passes over `store.devices` and `store.device_keys` the whole batch made. Each is a fixed number
    // however many devices the user holds.
    std::size_t device_table_passes{0U};
    std::size_t device_key_table_passes{0U};
};

} // namespace merovingian::federation
