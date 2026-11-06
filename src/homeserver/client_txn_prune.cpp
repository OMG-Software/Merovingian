// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/client_txn_prune.hpp"

#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/observability/logger.hpp"

#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>

namespace merovingian::homeserver
{

auto prune_client_transactions(HomeserverRuntime& runtime, std::chrono::system_clock::time_point now)
    -> std::chrono::milliseconds
{
    auto const now_ms = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count());
    // A clock before the retention window has nothing old enough to remove.
    if (now_ms > database::to_device_client_txn_retention_ms)
    {
        auto const cutoff_ms = now_ms - database::to_device_client_txn_retention_ms;
        auto const guard = RuntimeLock{runtime.mutex};
        auto const removed = database::prune_to_device_client_txns(runtime.database.persistent_store, cutoff_ms);
        if (removed > 0U)
        {
            LOG_INFO("Pruned expired to-device transaction records; removed=" + std::to_string(removed));
        }
    }
    return std::chrono::duration_cast<std::chrono::milliseconds>(client_txn_prune_interval);
}

} // namespace merovingian::homeserver
