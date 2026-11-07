// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::federation
{

// What an `m.device_list_update` did to the remote device-list cache (ADR-0561).
enum class RemoteDeviceListOutcome : std::uint8_t
{
    uncached,      // the user's list is not held; a local client must ask for it again
    unchanged,     // already applied, or applied and nothing a client sees changed
    changed,       // applied, and a device was added, changed or removed
    resync_needed, // a gap in the sequence, or the list was already stale: it is fetched again on the next query
};

} // namespace merovingian::federation
