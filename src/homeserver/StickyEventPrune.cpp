// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/StickyEventPrune.hpp"

#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/StickyEventStore.hpp"
#include "merovingian/database/StickyEventView.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/LocalDatabase.hpp"
#include "merovingian/observability/SingleLog.hpp"

#include <chrono>

namespace merovingian::homeserver
{

auto prune_sticky_events(HomeserverRuntime& runtime) -> std::chrono::milliseconds
{
    {
        auto const guard = RuntimeLock{runtime.mutex};
        auto& store = runtime.database.persistent_store;
        if (!database::prune_expired_sticky_events(store, database::sticky_clock_now_ms(store)))
        {
            LOG_WARNING("sticky_events.prune_failed");
        }
    }
    return std::chrono::duration_cast<std::chrono::milliseconds>(sticky_events_prune_interval);
}

} // namespace merovingian::homeserver
