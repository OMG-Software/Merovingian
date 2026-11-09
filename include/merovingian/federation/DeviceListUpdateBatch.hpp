// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>
#include <vector>

namespace merovingian::federation
{

// The `m.device_list_update` EDU contents announcing one local user's devices, built together
// (`build_device_list_update_batch`, security audit run-4 F-05, ADR-0582). Its cost is counted by
// `PersistentStore::device_table_rows_examined`, in rows read and not in time.
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
};

} // namespace merovingian::federation
